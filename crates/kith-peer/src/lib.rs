use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use kith_core::{DeliveryState, Identity, JmapError};
use kith_jmap::{HandlerFuture, JmapHandler};
#[cfg(any(test, feature = "test-utils"))]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(any(test, feature = "test-utils"))]
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
#[cfg(any(test, feature = "test-utils"))]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(any(test, feature = "test-utils"))]
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use ulid::Ulid;

/// Maximum body size accepted from a peer (bytes, matches KithChatCapability).
const MAX_BODY_BYTES: usize = 65_536;

/// Accepted body MIME types (matches KithChatCapability::supported_body_types).
const SUPPORTED_BODY_TYPES: &[&str] = &["text/plain", "text/markdown"];

// ---------------------------------------------------------------------------
// Peer/deliver — inbound handler
// ---------------------------------------------------------------------------

/// Wire args for the `Peer/deliver` JMAP method.
#[derive(Debug, Deserialize)]
pub struct PeerDeliverArgs {
    #[serde(rename = "accountId")]
    pub account_id: String,
    pub message: DeliverMessageArgs,
}

/// Attachment metadata as received in the Peer/deliver wire format.
#[derive(Debug, Deserialize, Serialize)]
pub struct AttachmentArg {
    #[serde(rename = "blobId")]
    pub blob_id: String,
    pub filename: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    pub size: u64,
    pub sha256: String,
}

/// The inner message object inside a `Peer/deliver` call.
#[derive(Debug, Deserialize)]
pub struct DeliverMessageArgs {
    pub id: String,
    #[serde(rename = "chatId")]
    pub chat_id: String,
    #[serde(rename = "senderUserId")]
    pub sender_user_id: String,
    pub body: String,
    #[serde(rename = "bodyType")]
    pub body_type: String,
    #[serde(rename = "replyTo")]
    pub reply_to: Option<String>,
    #[serde(rename = "sentAt")]
    pub sent_at: String,
    #[serde(default)]
    pub attachments: Vec<AttachmentArg>,
}

/// Handler for the `Peer/deliver` JMAP method.
///
/// Accepts an inbound message from a peer, validates it, and writes it to the
/// local message store.
///
/// # Identity injection
///
/// `JmapHandler::call` does not receive the caller identity directly.
/// The axum HTTP handler MUST inject the verified `Identity` into the `args`
/// JSON object under the private key `"_caller_identity"` before calling
/// `Dispatcher::dispatch`.  This handler extracts and removes that key.
///
/// # Validation order (mandatory — do not reorder)
///
/// 1. Extract `_caller_identity` from args.
/// 2. Parse remaining args into `PeerDeliverArgs`.
/// 3. `check_sender`: verify `senderUserId` equals the WhoIs identity.
/// 4. Enforce `maxBodyBytes`.
/// 5. Validate `bodyType` is supported.
/// 6. Validate message `id` is a well-formed ULID.
/// 7. (If `replyTo` present) verify the referenced message exists in this chat.
/// 8. `chats().get` or `create`; verify sender matches `contact_id` if chat exists.
/// 9. `messages().insert` with `delivery_state = Received`.
/// 10. `contacts().upsert`.
pub struct DeliverHandler {
    store: Arc<Mutex<kith_store::Store>>,
    owner_id: String,
}

impl DeliverHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>, owner_id: String) -> Self {
        Self { store, owner_id }
    }
}

impl JmapHandler for DeliverHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        mut args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);
        let _owner_id = self.owner_id.clone();

        Box::pin(async move {
            // Step 1: Extract caller identity injected by the axum layer.
            let identity: Identity = {
                let obj = args
                    .as_object_mut()
                    .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;
                let raw = obj.remove("_caller_identity").ok_or_else(|| {
                    JmapError::server_fail("caller identity not injected into args")
                })?;
                serde_json::from_value::<Identity>(raw).map_err(|_| {
                    JmapError::server_fail("caller identity value could not be deserialized")
                })?
            };

            // Step 2: Parse the public Peer/deliver arguments.
            let deliver: PeerDeliverArgs = serde_json::from_value(args)
                .map_err(|_| JmapError::invalid_arguments("invalid Peer/deliver arguments"))?;
            let msg = &deliver.message;

            // Step 3: check_sender — MUST occur before any DB write.
            // Maps SenderMismatch → invalidArguments per CLAUDE.md defensive rules.
            if identity.user_id != msg.sender_user_id {
                return Err(JmapError::invalid_arguments("senderUserId mismatch"));
            }

            // Step 4: Enforce maxBodyBytes.
            if msg.body.len() > MAX_BODY_BYTES {
                return Err(JmapError::invalid_arguments("body exceeds maxBodyBytes"));
            }

            // Step 6: Validate bodyType.
            if !SUPPORTED_BODY_TYPES.contains(&msg.body_type.as_str()) {
                return Err(JmapError::invalid_arguments("unsupported bodyType"));
            }

            // Step 7: Validate message id is a well-formed ULID.
            if msg.id.parse::<Ulid>().is_err() {
                return Err(JmapError::invalid_arguments(
                    "message id is not a valid ULID",
                ));
            }

            // Step 7.5: Validate attachment metadata (before lock acquisition).
            let attachments = validate_attachments(&msg.attachments)?;

            // Capture received_at before acquiring the store lock.
            let now_unix: i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                // System clock is always >= UNIX_EPOCH on any real deployment;
                // unwrap_or_default() guards against the impossible case without panic.
                .unwrap_or_default()
                .as_secs() as i64;
            let received_at = unix_secs_to_rfc3339(now_unix);

            // Acquire the store lock for all DB operations.
            let guard = store
                .lock()
                .map_err(|_| JmapError::server_fail("store lock poisoned"))?;

            // Step 7: Validate replyTo — referenced message must exist and be in this chat.
            if let Some(ref reply_id) = msg.reply_to {
                match guard.messages().get(reply_id) {
                    Ok(Some(ref referenced)) if referenced.chat_id == msg.chat_id => {}
                    Ok(Some(_)) => {
                        return Err(JmapError::invalid_arguments(
                            "replyTo references a message in a different chat",
                        ));
                    }
                    Ok(None) => {
                        return Err(JmapError::invalid_arguments(
                            "replyTo references a nonexistent message",
                        ));
                    }
                    Err(_) => {
                        return Err(JmapError::server_fail("store error checking replyTo"));
                    }
                }
            }

            // Step 8: Get or create the chat row using the peer-supplied chatId.
            // If the chat is unknown, create it with the sender as contact_id.
            // If the chat is known, verify the sender matches contact_id.
            match guard
                .chats()
                .get(&msg.chat_id)
                .map_err(|e| JmapError::server_fail(format!("store error looking up chat: {e}")))?
            {
                None => {
                    guard
                        .chats()
                        .create(
                            &msg.chat_id,
                            "direct",
                            Some(identity.user_id.as_str()),
                            now_unix,
                        )
                        .map_err(|e| {
                            JmapError::server_fail(format!("store error creating chat: {e}"))
                        })?;
                }
                Some(existing) => {
                    if existing.contact_id.as_deref() != Some(identity.user_id.as_str()) {
                        return Err(JmapError::invalid_arguments("chatId sender mismatch"));
                    }
                }
            }

            // Step 9: Idempotency check — if we've already received this sender_msg_id
            // for this chat, return the stored receivedAt without re-inserting.
            // The `?` propagates store errors so a transient DB failure can never
            // silently fall through to a duplicate insert.
            if let Some(ref existing) = guard
                .messages()
                .find_by_sender_msg_id(&msg.chat_id, &msg.id)
                .map_err(|e| {
                    JmapError::server_fail(format!("store error in idempotency check: {e}"))
                })?
            {
                return Ok(json!({
                    "accepted": true,
                    "id": existing.id,
                    "receivedAt": existing.received_at,
                }));
            }

            // Assign a fresh receiver-side ULID; the sender's id becomes sender_msg_id.
            let new_id = Ulid::new().to_string();

            // Step 9: Insert the message and its attachments in a single transaction.
            guard
                .insert_message_with_attachments(
                    &new_id,
                    &msg.chat_id,
                    &identity.user_id,
                    &msg.body,
                    &msg.body_type,
                    Some(msg.sent_at.as_str()),
                    now_unix,
                    &DeliveryState::Received,
                    msg.reply_to.as_deref(),
                    &msg.id,
                    &attachments,
                )
                .map_err(|e| {
                    JmapError::server_fail(format!("store error inserting message: {e}"))
                })?;

            // Update the chat's last_message_at so Chat/query ordering reflects
            // inbound messages.  Must run after the message insert so the timestamp
            // is always >= the message's created_at.
            guard
                .chats()
                .update_last_message_at(&msg.chat_id, now_unix)
                .map_err(|e| {
                    JmapError::server_fail(format!(
                        "store error updating chat last_message_at: {e}"
                    ))
                })?;

            // Step 10: Upsert the contact record for this peer.
            guard
                .contacts()
                .upsert(
                    &identity.user_id,
                    &identity.login_name,
                    &identity.node_name,
                    identity.display_name.as_deref(),
                    now_unix,
                )
                .map_err(|e| {
                    JmapError::server_fail(format!("store error upserting contact: {e}"))
                })?;

            drop(guard);

            Ok(json!({
                "accountId": "a-self",
                "accepted": true,
                "id": new_id,
                "receivedAt": received_at,
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Peer/receipt — inbound handler
// ---------------------------------------------------------------------------

/// Arguments for `Peer/receipt`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerReceiptArgs {
    pub account_id: String,
    pub message_id: String,
    pub kind: String,
    pub at: String,
}

/// Handler for the `Peer/receipt` JMAP method.
///
/// A remote peer calls this to report that a message this user sent has been
/// delivered to or read by the peer.  Only messages this daemon originated
/// (sender_id == "self") may be updated; all other IDs return `notFound` to
/// avoid leaking information about inbound messages.
pub struct ReceiptHandler {
    store: Arc<Mutex<kith_store::Store>>,
}

impl ReceiptHandler {
    pub fn new(store: Arc<Mutex<kith_store::Store>>) -> Self {
        Self { store }
    }
}

impl JmapHandler for ReceiptHandler {
    fn call(
        &self,
        _method_name: String,
        _call_id: String,
        mut args: serde_json::Value,
    ) -> HandlerFuture {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            // Step a: Extract caller identity injected by the axum layer.
            // Same protocol as DeliverHandler — identity is removed from args
            // before parsing so it is never visible to serde.
            let identity: Identity = {
                let obj = args
                    .as_object_mut()
                    .ok_or_else(|| JmapError::invalid_arguments("args must be a JSON object"))?;
                let raw = obj.remove("_caller_identity").ok_or_else(|| {
                    JmapError::server_fail("caller identity not injected into args")
                })?;
                serde_json::from_value::<Identity>(raw).map_err(|_| {
                    JmapError::server_fail("caller identity value could not be deserialized")
                })?
            };

            // Step b: parse remaining args.
            let parsed: PeerReceiptArgs = serde_json::from_value(args).map_err(|e| {
                JmapError::invalid_arguments(format!("invalid Peer/receipt arguments: {e}"))
            })?;

            // Step b: validate kind.
            if parsed.kind != "delivered" && parsed.kind != "read" {
                return Err(JmapError::invalid_arguments(format!(
                    "kind must be 'delivered' or 'read', got '{}'",
                    parsed.kind
                )));
            }

            // Step c: validate messageId is non-empty.
            if parsed.message_id.is_empty() {
                return Err(JmapError::invalid_arguments(
                    "messageId must not be empty".to_string(),
                ));
            }

            // Steps d-g: look up message and validate ownership.
            // We hold the lock only for the lookup+update block and drop it
            // before returning, keeping the critical section minimal.
            let now_unix: i64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                // System clock is always >= UNIX_EPOCH on any real deployment;
                // unwrap_or_default() guards against the impossible case without panic.
                .unwrap_or_default()
                .as_secs() as i64;

            let guard = store
                .lock()
                // A poisoned mutex means a previous handler panicked while holding
                // the lock, leaving the store in an unknown state.  Propagate as a
                // server error rather than panicking.
                .map_err(|_| JmapError::server_fail("store lock poisoned"))?;

            let msg = guard
                .messages()
                .get(&parsed.message_id)
                .map_err(|e| JmapError::server_fail(e.to_string()))?;

            // Step e: not found.
            let msg = msg.ok_or_else(JmapError::not_found)?;

            // Step f: ownership check -- only messages we sent may be updated.
            // Return not_found (not forbidden) to avoid distinguishing owned vs not-owned.
            if msg.sender_id != "self" {
                return Err(JmapError::not_found());
            }

            // Step g: inbound messages (Received state) are not ours to update.
            if msg.delivery_state == DeliveryState::Received {
                return Err(JmapError::not_found());
            }

            // Step h: verify the caller is the intended recipient of this message.
            // The chat's contact_id is the single peer authorised to send receipts
            // for messages in this conversation.  Return not_found (not forbidden)
            // to avoid leaking whether the message_id exists to an unauthorised caller.
            // Group chats (contact_id = None) are not yet supported for Peer/receipt.
            let chat = guard
                .chats()
                .get(&msg.chat_id)
                .map_err(|e| JmapError::server_fail(e.to_string()))?
                .ok_or_else(JmapError::not_found)?;
            if chat.contact_id.as_deref() != Some(identity.user_id.as_str()) {
                return Err(JmapError::not_found());
            }

            // Steps i-j: apply the state update.
            match parsed.kind.as_str() {
                "delivered" => {
                    guard
                        .messages()
                        .update_delivery_state(
                            &parsed.message_id,
                            &DeliveryState::Delivered,
                            Some(now_unix),
                        )
                        .map_err(|e| JmapError::server_fail(e.to_string()))?;
                }
                "read" => {
                    guard
                        .messages()
                        .update_read_at(&parsed.message_id, now_unix)
                        .map_err(|e| JmapError::server_fail(e.to_string()))?;
                }
                // Validated above; this arm is unreachable.
                _ => unreachable!("kind already validated to be 'delivered' or 'read'"),
            }

            // Step j: release lock (guard drops here) and return success.
            drop(guard);

            Ok(json!({
                "accountId": "a-self",
                "accepted": true
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Outbound HTTPS client for peer mailbox delivery
// ---------------------------------------------------------------------------

/// Maximum response body size accepted from a peer (1 MiB).
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Errors that can occur when delivering a message to a peer mailbox.
#[derive(Debug, Error)]
pub enum PeerDeliveryError {
    #[error("peer URL must use HTTPS")]
    InsecureUrl,
    #[error("delivery timed out")]
    Timeout,
    #[error("network error: {0}")]
    Network(String),
    #[error("peer returned HTTP {0}")]
    HttpError(u16),
    #[error("peer rejected delivery: {0}")]
    PeerRejected(String),
    #[error("peer response could not be parsed")]
    InvalidResponse,
}

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// A certificate verifier that accepts exactly one pinned DER-encoded certificate,
/// regardless of the hostname presented.
///
/// **WARNING:** This verifier BYPASSES hostname validation and expiry.
/// For test connections to self-signed certs ONLY.  Never use in production.
///
/// Signature verification is delegated to the platform `CryptoProvider`.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug)]
struct PinnedCertVerifier {
    /// DER bytes of the single trusted certificate.
    cert_der: Vec<u8>,
    /// Supported signature schemes, obtained from the active `CryptoProvider`.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

#[cfg(any(test, feature = "test-utils"))]
impl PinnedCertVerifier {
    fn new(cert_der: Vec<u8>) -> Self {
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        Self {
            cert_der,
            supported: provider.signature_verification_algorithms,
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref() == self.cert_der.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// An HTTPS client for delivering JMAP messages to peer mailboxes.
pub struct PeerHttpClient {
    client: HttpsClient,
}

impl PeerHttpClient {
    /// Construct a new client using the system WebPKI roots, HTTP/1.1 only.
    pub fn new() -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self { client }
    }

    /// Construct a client that trusts exactly one self-signed certificate.
    ///
    /// `cert_der` must be the DER-encoded end-entity certificate.  The client
    /// will accept that certificate regardless of the hostname in the TLS
    /// handshake, which makes it suitable for connecting to test servers that
    /// present a self-signed cert not issued for the loopback address.
    ///
    /// **WARNING:** This verifier BYPASSES hostname validation and expiry.
    /// For test connections to self-signed certs ONLY.  Never use in production.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_with_root_cert(cert_der: &[u8]) -> Self {
        let verifier = Arc::new(PinnedCertVerifier::new(cert_der.to_vec()));
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self { client }
    }

    /// Deliver a JMAP request to the peer's mailbox URL.
    ///
    /// The URL must start with `https://`. A 30-second timeout is applied to
    /// the entire round trip. The response body is limited to 1 MiB.
    pub async fn deliver(&self, url: &str, jmap_request: Value) -> Result<(), PeerDeliveryError> {
        if !url.starts_with("https://") {
            return Err(PeerDeliveryError::InsecureUrl);
        }

        let body_bytes = serde_json::to_vec(&jmap_request)
            .map_err(|e| PeerDeliveryError::Network(e.to_string()))?;

        let result = tokio::time::timeout(Duration::from_secs(30), async {
            let req = Request::builder()
                .method(hyper::Method::POST)
                .uri(url)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body_bytes)))
                .map_err(|e: hyper::http::Error| PeerDeliveryError::Network(e.to_string()))?;

            let resp = self
                .client
                .request(req)
                .await
                .map_err(|e| PeerDeliveryError::Network(e.to_string()))?;

            let status = resp.status();
            if !status.is_success() {
                return Err(PeerDeliveryError::HttpError(status.as_u16()));
            }

            let raw = Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|_| PeerDeliveryError::Network("reading response body failed".into()))?
                .to_bytes();

            let parsed: Value =
                serde_json::from_slice(&raw).map_err(|_| PeerDeliveryError::InvalidResponse)?;

            // Check for a JMAP-level error in methodResponses[0][1].
            if let Some(error_type) = parsed
                .pointer("/methodResponses/0/1/type")
                .and_then(|v| v.as_str())
            {
                return Err(PeerDeliveryError::PeerRejected(error_type.to_string()));
            }

            // Expect accepted == true.
            match parsed.pointer("/methodResponses/0/1/accepted") {
                Some(Value::Bool(true)) => Ok(()),
                _ => Err(PeerDeliveryError::InvalidResponse),
            }
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => Err(PeerDeliveryError::Timeout),
        }
    }
}

impl Default for PeerHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a `Peer/deliver` JMAP request envelope.
///
/// Returns the full JMAP envelope ready to be sent as a JSON body.
/// The params are structured as `PeerDeliverArgs` expects: `accountId` and
/// a nested `message` object containing `id`, `chatId`, etc.
#[allow(clippy::too_many_arguments)]
pub fn build_peer_deliver_request(
    message_id: &str,
    chat_id: &str,
    sender_user_id: &str,
    body: &str,
    body_type: &str,
    sent_at: &str,
    reply_to: Option<&str>,
    attachments: &[kith_core::Attachment],
) -> Value {
    let mut message = json!({
        "id": message_id,
        "chatId": chat_id,
        "senderUserId": sender_user_id,
        "body": body,
        "bodyType": body_type,
        "sentAt": sent_at,
        "attachments": attachments.iter().map(|a| json!({
            "blobId": a.blob_id,
            "filename": a.filename,
            "contentType": a.content_type,
            "size": a.size,
            "sha256": a.sha256,
        })).collect::<Vec<Value>>(),
    });

    if let Some(reply_id) = reply_to {
        message["replyTo"] = Value::String(reply_id.to_string());
    }

    json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Peer/deliver", {
            "accountId": "a-self",
            "message": message,
        }, "0"]],
    })
}

/// Build a `Peer/receipt` JMAP request envelope.
///
/// Notifies the original sender that we read their message.
/// `message_id` is the ID of the message being receipted.
/// `kind` is "read" (the only kind sent by kith; "delivered" is reserved for future use).
/// `at` is an RFC 3339 UTC timestamp string.
pub fn build_peer_receipt_request(message_id: &str, kind: &str, at: &str) -> Value {
    json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [[
            "Peer/receipt",
            {
                "accountId": "a-self",
                "messageId": message_id,
                "kind": kind,
                "at": at,
            },
            "0"
        ]]
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Validate attachment metadata from a `Peer/deliver` request.
///
/// Returns validated `kith_core::Attachment` values ready for storage, or an
/// `invalidArguments` error describing the first violation found.
///
/// This function validates only metadata — it does NOT fetch or verify blob data.
/// All field constraints match the `KithChatCapability` spec.
fn validate_attachments(
    attachments: &[AttachmentArg],
) -> Result<Vec<kith_core::Attachment>, JmapError> {
    const MAX_ATTACHMENTS: usize = 20;
    const MAX_ATTACHMENT_BYTES: u64 = 104_857_600; // 100 MiB

    if attachments.len() > MAX_ATTACHMENTS {
        return Err(JmapError::invalid_arguments("too many attachments"));
    }

    let mut result = Vec::with_capacity(attachments.len());
    for a in attachments {
        // Validate blob_id: [a-zA-Z0-9_-], 1–128 chars, no leading dot.
        if a.blob_id.is_empty() || a.blob_id.len() > 128 || a.blob_id.starts_with('.') {
            return Err(JmapError::invalid_arguments("invalid attachment blobId"));
        }
        if !a
            .blob_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(JmapError::invalid_arguments("invalid attachment blobId"));
        }

        // Validate filename: non-empty, max 255, no path traversal.
        if a.filename.is_empty() || a.filename.len() > 255 {
            return Err(JmapError::invalid_arguments("invalid attachment filename"));
        }
        if a.filename.starts_with('.')
            || a.filename.contains('/')
            || a.filename.contains('\\')
            || a.filename.contains('\x00')
            || a.filename.contains("..")
        {
            return Err(JmapError::invalid_arguments("unsafe attachment filename"));
        }

        // Validate content_type: non-empty, max 256, exactly one '/', non-empty
        // type and subtype on each side.
        if a.content_type.is_empty() || a.content_type.len() > 256 {
            return Err(JmapError::invalid_arguments(
                "invalid attachment contentType",
            ));
        }
        match a.content_type.split_once('/') {
            Some((t, s)) if !t.is_empty() && !s.is_empty() => {} // valid
            _ => {
                return Err(JmapError::invalid_arguments(
                    "invalid attachment contentType",
                ))
            }
        }

        // Validate size: non-zero and within the per-attachment cap.
        if a.size == 0 || a.size > MAX_ATTACHMENT_BYTES {
            return Err(JmapError::invalid_arguments("invalid attachment size"));
        }

        // Validate sha256: exactly 64 lowercase hex characters.
        if a.sha256.len() != 64 || !a.sha256.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(JmapError::invalid_arguments("invalid attachment sha256"));
        }

        result.push(kith_core::Attachment {
            blob_id: a.blob_id.clone(),
            filename: a.filename.clone(),
            content_type: a.content_type.clone(),
            size: a.size,
            sha256: a.sha256.clone(),
        });
    }
    Ok(result)
}

/// Returns `true` if `host` is safe to embed in an HTTPS URL authority component.
///
/// Accepts `[a-zA-Z0-9.-]` as hostname characters and an optional `:[0-9]+` port suffix.
/// Rejects anything that could enable host-header injection or URL manipulation
/// (`@`, `/`, `?`, `#`, `%`, whitespace, etc.).
fn is_valid_mailbox_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let name = match host.rfind(':') {
        Some(i) => {
            let port = &host[i + 1..];
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            &host[..i]
        }
        None => host,
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Format a Unix timestamp (seconds since epoch) as an RFC 3339 UTC string.
///
/// Duplicates the algorithm from `kith-store`'s private util module so that
/// `kith-peer` does not depend on store internals.
/// Algorithm: Hinnant civil-calendar (https://howardhinnant.github.io/date_algorithms.html).
fn unix_secs_to_rfc3339(secs: i64) -> String {
    let secs_in_day: i64 = 86400;
    let days = secs.div_euclid(secs_in_day);
    let time_secs = secs.rem_euclid(secs_in_day);

    let hh = time_secs / 3600;
    let mm = (time_secs % 3600) / 60;
    let ss = time_secs % 60;

    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

// ---------------------------------------------------------------------------
// Outbox worker
// ---------------------------------------------------------------------------

/// Abstraction over HTTPS delivery for testability.
///
/// `PeerHttpClient` implements this trait.  Tests supply a `MockClient`.
pub trait DeliverClient: Send + 'static {
    fn deliver_msg<'a>(
        &'a self,
        url: &'a str,
        request: Value,
    ) -> impl std::future::Future<Output = Result<(), PeerDeliveryError>> + Send + 'a;
}

impl DeliverClient for PeerHttpClient {
    fn deliver_msg<'a>(
        &'a self,
        url: &'a str,
        request: Value,
    ) -> impl std::future::Future<Output = Result<(), PeerDeliveryError>> + Send + 'a {
        self.deliver(url, request)
    }
}

/// One poll cycle of the outbox worker.
///
/// Fetches all outbox entries due by `now_unix`, re-validates each contact,
/// and attempts delivery via `client`.  All store lock acquisitions are
/// released before any `.await` — never hold the lock across a sleep or an
/// HTTP call.
pub async fn outbox_tick<C: DeliverClient>(
    store: &Arc<Mutex<kith_store::Store>>,
    client: &C,
    owner_id: &str,
    now_unix: i64,
) {
    // Phase 1: fetch due entries; hold lock only for this SQLite call.
    let due = {
        let guard = match store.lock() {
            Ok(g) => g,
            Err(_) => {
                eprintln!("outbox: store lock poisoned getting due entries");
                return;
            }
        };
        match guard.outbox().get_due(now_unix) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!("outbox: get_due failed: {err}");
                return;
            }
        }
    }; // guard dropped here

    // Phase 2: process each entry serially (Phase 1 constraint).
    for entry in due {
        // Re-validate contact: may have been blocked since enqueue.
        let contact_result = {
            let guard = match store.lock() {
                Ok(g) => g,
                Err(_) => continue,
            };
            guard.contacts().get_by_peer_user_id(&entry.peer_user_id)
        }; // guard dropped here

        match contact_result {
            Ok(Some(c)) if !c.blocked => {
                let _ = c;
            }
            Ok(_) => {
                // Not found or blocked — record failure and move on.
                if let Ok(guard) = store.lock() {
                    let _ = guard.outbox().record_failure(
                        &entry,
                        "contact not found or blocked",
                        now_unix,
                    );
                }
                continue;
            }
            Err(err) => {
                eprintln!("outbox: contact lookup error: {err}");
                continue;
            }
        };

        if !is_valid_mailbox_host(&entry.peer_mailbox_host) {
            eprintln!(
                "outbox: rejecting invalid mailbox_host for {}: {:?}",
                entry.peer_user_id, entry.peer_mailbox_host
            );
            if let Ok(guard) = store.lock() {
                let _ = guard
                    .outbox()
                    .record_failure(&entry, "invalid mailbox_host", now_unix);
            }
            continue;
        }
        let url = format!("https://{}/jmap/api", entry.peer_mailbox_host);

        // Receipt entries do not need message body or chat data — handle them here
        // and skip the message-specific code below.
        if entry.kind == "receipt" {
            let read_at_unix = match entry.read_at_unix {
                Some(ts) => ts,
                None => {
                    eprintln!(
                        "outbox: receipt entry missing read_at_unix for {}",
                        entry.message_id
                    );
                    if let Ok(guard) = store.lock() {
                        let _ = guard.outbox().record_failure(
                            &entry,
                            "receipt missing read_at_unix",
                            now_unix,
                        );
                    }
                    continue;
                }
            };
            let at_str = unix_secs_to_rfc3339(read_at_unix);
            let jmap_request = build_peer_receipt_request(&entry.message_id, "read", &at_str);
            match client.deliver_msg(&url, jmap_request).await {
                Ok(()) => {
                    if let Ok(guard) = store.lock() {
                        let _ = guard.outbox().complete_delivery(&entry, now_unix);
                    }
                    eprintln!("outbox: delivered receipt for {}", entry.message_id);
                }
                Err(err) => {
                    if let Ok(guard) = store.lock() {
                        let _ = guard
                            .outbox()
                            .record_failure(&entry, &err.to_string(), now_unix);
                    }
                    eprintln!(
                        "outbox: receipt delivery failed for {}: {err}",
                        entry.message_id
                    );
                }
            }
            continue;
        }

        // Load message payload; hold lock only for this call.
        // Lock discipline: MutexGuard<Store> is !Send, so the compiler enforces
        // that it cannot be held across an .await point. The block below ensures
        // the guard is dropped before any async I/O begins.
        let message_result = {
            let guard = match store.lock() {
                Ok(g) => g,
                Err(_) => continue,
            };
            guard.messages().get(&entry.message_id)
        }; // guard dropped here

        let message = match message_result {
            Ok(Some(m)) => m,
            Ok(None) => {
                // Message was deleted by owner — orphaned outbox row cleanup only.
                // Use mark_delivered (DELETE only), not complete_delivery, because
                // there is no message row to update.
                if let Ok(guard) = store.lock() {
                    let _ = guard.outbox().mark_delivered(&entry);
                }
                continue;
            }
            Err(err) => {
                eprintln!("outbox: message load error: {err}");
                continue;
            }
        };

        // Build JMAP request; owner_id replaces the "self" sentinel in sender_id.
        let jmap_request = build_peer_deliver_request(
            &message.id,
            &message.chat_id,
            owner_id,
            &message.body,
            &message.body_type,
            &message.sent_at,
            message.reply_to.as_deref(),
            message.attachments.as_slice(),
        );

        // Attempt delivery — no lock held across this await.
        match client.deliver_msg(&url, jmap_request).await {
            Ok(()) => {
                if let Ok(guard) = store.lock() {
                    let _ = guard.outbox().complete_delivery(&entry, now_unix);
                }
                eprintln!("outbox: delivered {}", entry.message_id);
            }
            Err(err) => {
                if let Ok(guard) = store.lock() {
                    let _ = guard
                        .outbox()
                        .record_failure(&entry, &err.to_string(), now_unix);
                }
                eprintln!("outbox: delivery failed for {}: {err}", entry.message_id);
            }
        }
    }
}

/// Outbox worker: polls the outbox every 30 seconds and retries pending entries.
///
/// Runs forever (`-> !`).  Spawn with `tokio::spawn`.
///
/// # Lock discipline
///
/// The store lock is always dropped before any `.await`.  This is enforced by
/// the borrow checker: `MutexGuard<'_, Store>` is not `Send`, so holding one
/// across an `.await` point would be a compile error.
pub async fn outbox_worker<C: DeliverClient>(
    store: Arc<Mutex<kith_store::Store>>,
    client: C,
    owner_id: String,
) -> ! {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        outbox_tick(&store, &client, &owner_id, now_unix).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_core::{DeliveryState, Identity};
    use kith_store::Store;
    use serde_json::json;
    use ulid::Ulid;

    /// Install the aws-lc-rs CryptoProvider for tests that construct TLS clients.
    /// Safe to call multiple times; subsequent calls are no-ops.
    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn make_store() -> Arc<Mutex<Store>> {
        Arc::new(Mutex::new(
            Store::open_in_memory().expect("open in-memory store"),
        ))
    }

    /// Insert a direct chat with a specific contact_id.
    ///
    /// Use this in ReceiptHandler tests so the caller-identity check can pass:
    /// pass the same `contact_id` as the `user_id` in `_caller_identity`.
    fn insert_chat_with_contact(store: &Arc<Mutex<Store>>, chat_id: &str, contact_id: &str) {
        let guard = store.lock().unwrap();
        guard
            .chats()
            .create(chat_id, "direct", Some(contact_id), 1000)
            .expect("insert chat with contact");
    }

    /// Insert a message row via the public MessageStore API.
    fn insert_msg(
        store: &Arc<Mutex<Store>>,
        id: &str,
        chat_id: &str,
        sender_id: &str,
        delivery_state: &DeliveryState,
    ) {
        let guard = store.lock().unwrap();
        guard
            .messages()
            .insert(
                id,
                chat_id,
                sender_id,
                "body",
                "text/plain",
                None,
                1000,
                delivery_state,
                None,
                id,
            )
            .expect("insert message");
    }

    /// Build the args JSON for a DeliverHandler call, injecting the identity.
    fn deliver_args(
        identity: &Identity,
        _owner_id: &str,
        msg_id: &str,
        body: &str,
    ) -> serde_json::Value {
        let chat_id = "test-direct-chat-01";
        let identity_json = serde_json::to_value(identity).unwrap();
        json!({
            "_caller_identity": identity_json,
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": chat_id,
                "senderUserId": identity.user_id,
                "body": body,
                "bodyType": "text/plain",
                "sentAt": "2026-04-19T12:00:00Z",
            }
        })
    }

    fn make_identity(user_id: &str) -> Identity {
        Identity {
            user_id: user_id.to_string(),
            login_name: format!("{user_id}@example.com"),
            display_name: Some(format!("User {user_id}")),
            node_name: format!("{user_id}-node.tail12345.ts.net"),
        }
    }

    // ---------------------------------------------------------------------------
    // DeliverHandler tests
    // Oracle: spec defined in CLAUDE.md and bead KITH-efh.
    // Expected values are derived from the spec, not from running the code.
    // ---------------------------------------------------------------------------

    // Oracle: a valid Peer/deliver call must return accepted=true and a receivedAt timestamp.
    #[tokio::test]
    async fn deliver_valid_message_accepted() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");

        let msg_id = Ulid::new().to_string();
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let result = handler
            .call(
                "Peer/deliver".to_string(),
                "c0".to_string(),
                deliver_args(&peer, owner_id, &msg_id, "Hello!"),
            )
            .await;

        let val = result.expect("valid delivery should succeed");
        assert_eq!(val["accountId"], "a-self");
        assert_eq!(val["accepted"], true);
        assert!(
            val["receivedAt"].as_str().is_some(),
            "receivedAt must be a string"
        );

        // Oracle: the message is in the store under the receiver-assigned id (val["id"]).
        let received_id = val["id"].as_str().expect("id must be a string in response");
        let guard = store.lock().unwrap();
        let msg = guard
            .messages()
            .get(received_id)
            .unwrap()
            .expect("message must exist in store");
        assert_eq!(msg.delivery_state, DeliveryState::Received);
        assert_eq!(msg.sender_id, "uid-bob");
        assert_eq!(msg.body, "Hello!");
        assert_eq!(
            msg.sender_msg_id, msg_id,
            "sender_msg_id must equal the sender's ULID"
        );
    }

    // Oracle: after a valid delivery, the contact must be upserted.
    #[tokio::test]
    async fn deliver_upserts_contact() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let msg_id = Ulid::new().to_string();

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        handler
            .call(
                "Peer/deliver".to_string(),
                "c0".to_string(),
                deliver_args(&peer, owner_id, &msg_id, "Hi"),
            )
            .await
            .expect("delivery should succeed");

        // Oracle: contact row must exist with the peer's user_id.
        let guard = store.lock().unwrap();
        let permitted = guard.contacts().is_permitted("uid-bob").unwrap();
        assert!(permitted, "peer must be in contacts after delivery");
    }

    // Oracle: senderUserId mismatch must return invalidArguments before any DB write.
    #[tokio::test]
    async fn deliver_sender_mismatch_returns_invalid_arguments() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");

        // Build args but override the senderUserId to a different value.
        let chat_id = "test-direct-chat-02";
        let msg_id = Ulid::new().to_string();
        let identity_json = serde_json::to_value(&peer).unwrap();
        let args = json!({
            "_caller_identity": identity_json,
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": chat_id,
                "senderUserId": "uid-evil",  // mismatch
                "body": "Hi",
                "bodyType": "text/plain",
                "sentAt": "2026-04-19T12:00:00Z",
            }
        });

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("sender mismatch must fail");

        assert_eq!(err.error_type, "invalidArguments");
        // Oracle: check_sender failure must precede any DB write — no message inserted.
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on sender mismatch"
        );
    }

    // Oracle: a chat pre-created with contact_id=uid-alice must reject a deliver from uid-bob.
    // The new server-assigned model stores the sender's user_id as contact_id; a different
    // sender claiming the same chatId is rejected with invalidArguments.
    #[tokio::test]
    async fn deliver_chatid_sender_mismatch_returns_invalid_arguments() {
        let store = make_store();
        let owner_id = "uid-owner";
        let bob = make_identity("uid-bob");

        // Pre-create a chat whose contact_id is uid-alice (not uid-bob).
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-alice-owned", "direct", Some("uid-alice"), 1000)
                .expect("pre-create chat");
        }

        // uid-bob tries to deliver into a chat that belongs to uid-alice.
        let msg_id = Ulid::new().to_string();
        let identity_json = serde_json::to_value(&bob).unwrap();
        let args = json!({
            "_caller_identity": identity_json,
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": "chat-alice-owned",
                "senderUserId": "uid-bob",
                "body": "Hi",
                "bodyType": "text/plain",
                "sentAt": "2026-04-19T12:00:00Z",
            }
        });

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("sender mismatch on existing chat must fail");

        assert_eq!(err.error_type, "invalidArguments");
        // Oracle: mismatch check precedes message insert — no message must be stored.
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on chatId sender mismatch"
        );
    }

    // Oracle: body exceeding MAX_BODY_BYTES must return invalidArguments.
    #[tokio::test]
    async fn deliver_oversized_body_returns_invalid_arguments() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");

        let oversized_body = "x".repeat(MAX_BODY_BYTES + 1);
        let msg_id = Ulid::new().to_string();

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call(
                "Peer/deliver".to_string(),
                "c0".to_string(),
                deliver_args(&peer, owner_id, &msg_id, &oversized_body),
            )
            .await
            .expect_err("oversized body must fail");

        assert_eq!(err.error_type, "invalidArguments");
        // Oracle: body size check precedes DB writes — no message must be stored.
        let guard = store.lock().unwrap(); // safe: single-threaded test
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on oversized body"
        );
    }

    // Oracle: unsupported bodyType must return invalidArguments.
    #[tokio::test]
    async fn deliver_unsupported_body_type_returns_invalid_arguments() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");

        let msg_id = Ulid::new().to_string();
        let identity_json = serde_json::to_value(&peer).unwrap();
        let args = json!({
            "_caller_identity": identity_json,
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": "test-direct-chat-03",
                "senderUserId": peer.user_id,
                "body": "Hi",
                "bodyType": "text/html",   // not supported
                "sentAt": "2026-04-19T12:00:00Z",
            }
        });

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("unsupported bodyType must fail");

        assert_eq!(err.error_type, "invalidArguments");
        // Oracle: bodyType check precedes DB writes — no message must be stored.
        let guard = store.lock().unwrap(); // safe: single-threaded test
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on unsupported bodyType"
        );
    }

    // Oracle: non-ULID message id must return invalidArguments.
    #[tokio::test]
    async fn deliver_non_ulid_message_id_returns_invalid_arguments() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");

        let identity_json = serde_json::to_value(&peer).unwrap();
        let args = json!({
            "_caller_identity": identity_json,
            "accountId": "a-self",
            "message": {
                "id": "not-a-ulid",
                "chatId": "test-direct-chat-04",
                "senderUserId": peer.user_id,
                "body": "Hi",
                "bodyType": "text/plain",
                "sentAt": "2026-04-19T12:00:00Z",
            }
        });

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("non-ULID id must fail");

        assert_eq!(err.error_type, "invalidArguments");
        // Oracle: ULID check precedes DB writes — message "not-a-ulid" must not be stored.
        let guard = store.lock().unwrap(); // safe: single-threaded test
        assert!(
            guard.messages().get("not-a-ulid").unwrap().is_none(),
            "no message must be stored on invalid ULID"
        );
    }

    // Oracle: replyTo referencing a nonexistent message must return invalidArguments.
    #[tokio::test]
    async fn deliver_reply_to_nonexistent_returns_invalid_arguments() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");

        let msg_id = Ulid::new().to_string();
        let identity_json = serde_json::to_value(&peer).unwrap();
        let args = json!({
            "_caller_identity": identity_json,
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": "test-direct-chat-05",
                "senderUserId": peer.user_id,
                "body": "Hi",
                "bodyType": "text/plain",
                "sentAt": "2026-04-19T12:00:00Z",
                "replyTo": "does-not-exist",
            }
        });

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("replyTo nonexistent must fail");

        assert_eq!(err.error_type, "invalidArguments");
        // Oracle: replyTo check precedes message insert — no message must be stored.
        let guard = store.lock().unwrap(); // safe: single-threaded test
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored when replyTo is invalid"
        );
    }

    // Oracle: replyTo referencing a message in a different chat must return invalidArguments.
    // Lines 168-171 of DeliverHandler handle this case; this test covers that branch.
    #[tokio::test]
    async fn deliver_reply_to_different_chat_returns_invalid_arguments() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");

        // Insert a message in a different chat (alice→owner, not bob→owner).
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create("chat-alice-06", "direct", Some("uid-alice"), 1000)
                .unwrap();
            guard
                .messages()
                .insert(
                    "other-chat-msg",
                    "chat-alice-06",
                    "uid-alice",
                    "hi",
                    "text/plain",
                    None,
                    1000,
                    &DeliveryState::Received,
                    None,
                    "other-chat-msg",
                )
                .unwrap();
        }

        let msg_id = Ulid::new().to_string();
        let identity_json = serde_json::to_value(&peer).unwrap();
        let args = json!({
            "_caller_identity": identity_json,
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": "test-direct-chat-06",
                "senderUserId": peer.user_id,
                "body": "reply to wrong chat",
                "bodyType": "text/plain",
                "sentAt": "2026-04-19T12:00:00Z",
                "replyTo": "other-chat-msg",
            }
        });

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("replyTo in different chat must fail");

        assert_eq!(err.error_type, "invalidArguments");
        // Oracle: replyTo check precedes message insert — no new message must be stored.
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored when replyTo references a different chat"
        );
    }

    // Oracle: missing _caller_identity must return serverFail (not invalidArguments).
    #[tokio::test]
    async fn deliver_missing_identity_returns_server_fail() {
        let store = make_store();
        let owner_id = "uid-owner";

        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call(
                "Peer/deliver".to_string(),
                "c0".to_string(),
                json!({"accountId": "a-self", "message": {}}),
            )
            .await
            .expect_err("missing identity must fail");

        assert_eq!(err.error_type, "serverFail");
        // Oracle: identity extraction fails before any DB write — store must be empty.
        let guard = store.lock().unwrap(); // safe: single-threaded test
        let state_str = guard.messages().get_state().unwrap();
        // State "s-0" means no messages have ever been inserted (counter never advanced).
        assert_eq!(
            state_str, "s-0",
            "no message state advance must occur when identity is missing"
        );
    }

    // ---------------------------------------------------------------------------
    // ReceiptHandler tests
    // Oracle: expected values derived from spec, not from running the implementation.
    // ---------------------------------------------------------------------------

    // Oracle: a well-formed Peer/receipt for an outbound "delivered" receipt
    // must return {"accountId": "a-self", "accepted": true}.
    #[tokio::test]
    async fn receipt_delivered_accepted() {
        let store = make_store();
        // contact_id must match the caller identity below.
        insert_chat_with_contact(&store, "chat-r1", "uid-bob");
        insert_msg(&store, "msg-r1", "chat-r1", "self", &DeliveryState::Pending);

        let caller = make_identity("uid-bob");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&caller).unwrap(),
                    "accountId": "a-self",
                    "messageId": "msg-r1",
                    "kind": "delivered",
                    "at": "2026-04-19T00:00:00Z"
                }),
            )
            .await;

        let val = result.expect("should succeed");
        assert_eq!(val["accountId"], "a-self");
        assert_eq!(val["accepted"], true);

        // Oracle: the message's delivery_state must now be Delivered.
        let guard = store.lock().unwrap();
        let msg = guard.messages().get("msg-r1").unwrap().unwrap();
        assert_eq!(msg.delivery_state, DeliveryState::Delivered);
        assert!(msg.delivered_at.is_some(), "delivered_at must be set");
    }

    // Oracle: a "read" receipt must set read_at on the message row.
    #[tokio::test]
    async fn receipt_read_accepted() {
        let store = make_store();
        insert_chat_with_contact(&store, "chat-r2", "uid-bob");
        insert_msg(
            &store,
            "msg-r2",
            "chat-r2",
            "self",
            &DeliveryState::Delivered,
        );

        let caller = make_identity("uid-bob");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&caller).unwrap(),
                    "accountId": "a-self",
                    "messageId": "msg-r2",
                    "kind": "read",
                    "at": "2026-04-19T00:01:00Z"
                }),
            )
            .await;

        assert!(result.is_ok(), "expected Ok, got: {:?}", result);

        let guard = store.lock().unwrap();
        let msg = guard.messages().get("msg-r2").unwrap().unwrap();
        assert!(
            msg.read_at.is_some(),
            "read_at must be set after 'read' receipt"
        );
    }

    // Oracle: a receipt for a message whose sender_id != "self" must return notFound.
    #[tokio::test]
    async fn receipt_for_inbound_message_returns_not_found() {
        let store = make_store();
        insert_chat_with_contact(&store, "chat-r3", "uid-peer");
        insert_msg(
            &store,
            "msg-r3",
            "chat-r3",
            "uid-peer",
            &DeliveryState::Received,
        );

        let caller = make_identity("uid-peer");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&caller).unwrap(),
                    "accountId": "a-self",
                    "messageId": "msg-r3",
                    "kind": "delivered",
                    "at": "2026-04-19T00:00:00Z"
                }),
            )
            .await;

        let err = result.expect_err("should return notFound");
        assert_eq!(err.error_type, "notFound");
    }

    // Oracle: a receipt for a nonexistent message must return notFound.
    #[tokio::test]
    async fn receipt_for_nonexistent_message_returns_not_found() {
        let store = make_store();

        let caller = make_identity("uid-bob");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&caller).unwrap(),
                    "accountId": "a-self",
                    "messageId": "does-not-exist",
                    "kind": "delivered",
                    "at": "2026-04-19T00:00:00Z"
                }),
            )
            .await;

        let err = result.expect_err("should return notFound");
        assert_eq!(err.error_type, "notFound");
    }

    // Oracle: an unknown kind must return invalidArguments.
    #[tokio::test]
    async fn receipt_invalid_kind_returns_invalid_arguments() {
        let store = make_store();
        insert_chat_with_contact(&store, "chat-r4", "uid-bob");
        insert_msg(&store, "msg-r4", "chat-r4", "self", &DeliveryState::Pending);

        let caller = make_identity("uid-bob");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&caller).unwrap(),
                    "accountId": "a-self",
                    "messageId": "msg-r4",
                    "kind": "bounced",
                    "at": "2026-04-19T00:00:00Z"
                }),
            )
            .await;

        let err = result.expect_err("should return invalidArguments");
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Oracle: empty messageId must return invalidArguments.
    #[tokio::test]
    async fn receipt_empty_message_id_returns_invalid_arguments() {
        let store = make_store();

        let caller = make_identity("uid-bob");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&caller).unwrap(),
                    "accountId": "a-self",
                    "messageId": "",
                    "kind": "delivered",
                    "at": "2026-04-19T00:00:00Z"
                }),
            )
            .await;

        let err = result.expect_err("should return invalidArguments");
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Oracle: sender_id == "self" but delivery_state == Received must return notFound.
    #[tokio::test]
    async fn receipt_self_sender_but_received_state_returns_not_found() {
        let store = make_store();
        insert_chat_with_contact(&store, "chat-r5", "uid-bob");
        insert_msg(
            &store,
            "msg-r5",
            "chat-r5",
            "self",
            &DeliveryState::Received,
        );

        let caller = make_identity("uid-bob");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&caller).unwrap(),
                    "accountId": "a-self",
                    "messageId": "msg-r5",
                    "kind": "delivered",
                    "at": "2026-04-19T00:00:00Z"
                }),
            )
            .await;

        let err = result.expect_err("should return notFound");
        assert_eq!(err.error_type, "notFound");
    }

    // Oracle: malformed args (after identity extraction) must return invalidArguments.
    #[tokio::test]
    async fn receipt_malformed_args_returns_invalid_arguments() {
        let store = make_store();
        let caller = make_identity("uid-bob");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&caller).unwrap(),
                    "not": "a valid receipt"
                }),
            )
            .await;

        let err = result.expect_err("should return invalidArguments");
        assert_eq!(err.error_type, "invalidArguments");
    }

    // Oracle: a Peer/receipt from a contact that is NOT the chat's contact_id must
    // return notFound.  This is the core security boundary: only the peer the
    // message was actually sent to may update its delivery state.
    //
    // Independent oracle: the DB has no message state change; delivery_state
    // remains Pending — verified by reading the message after the rejected call.
    #[tokio::test]
    async fn receipt_wrong_contact_returns_not_found() {
        let store = make_store();
        // Chat belongs to uid-bob; message was sent by "self" to uid-bob.
        insert_chat_with_contact(&store, "chat-rwc", "uid-bob");
        insert_msg(
            &store,
            "msg-rwc",
            "chat-rwc",
            "self",
            &DeliveryState::Pending,
        );

        // uid-eve is a valid contact but NOT the recipient of this message.
        let eve = make_identity("uid-eve");
        let handler = ReceiptHandler::new(Arc::clone(&store));
        let result = handler
            .call(
                "Peer/receipt".to_string(),
                "c0".to_string(),
                json!({
                    "_caller_identity": serde_json::to_value(&eve).unwrap(),
                    "accountId": "a-self",
                    "messageId": "msg-rwc",
                    "kind": "delivered",
                    "at": "2026-04-19T00:00:00Z"
                }),
            )
            .await;

        let err =
            result.expect_err("uid-eve must not be able to forge a receipt for uid-bob's message");
        assert_eq!(
            err.error_type, "notFound",
            "wrong-contact rejection must return notFound"
        );

        // Independent oracle: delivery_state must still be Pending — the call must
        // have made no state change.
        let guard = store.lock().unwrap();
        let msg = guard.messages().get("msg-rwc").unwrap().unwrap();
        assert_eq!(
            msg.delivery_state,
            DeliveryState::Pending,
            "delivery_state must remain Pending after rejected receipt"
        );
    }

    // ---------------------------------------------------------------------------
    // PeerHttpClient / build_peer_deliver_request tests
    // Oracle: kith-architecture.md §Wire Protocol + RFC 8620 §3.2
    // ---------------------------------------------------------------------------

    // Oracle: CLAUDE.md §Defensive Input Handling — URL must use HTTPS.
    // Receiving InsecureUrl (not NetworkError) proves the check runs before connect.
    // Port 1 is privileged and not listening; if a connect were attempted the OS
    // would return ECONNREFUSED which maps to Network, not InsecureUrl.
    #[tokio::test]
    async fn insecure_url_rejected_without_network_call() {
        install_crypto_provider();
        let client = PeerHttpClient::new();
        let req = build_peer_deliver_request(
            "01JVWXYZ0000000000000000AB",
            &"b3d4e5f6".repeat(8),
            "uid:alice@example.com",
            "hello",
            "text/plain",
            "2026-04-18T20:14:00Z",
            None,
            &[],
        );
        let result = client.deliver("http://127.0.0.1:1/jmap", req).await;
        assert!(
            matches!(result, Err(PeerDeliveryError::InsecureUrl)),
            "http:// URL must return InsecureUrl, got: {:?}",
            result
        );
    }

    // Oracle: RFC 8620 §3.2 — JMAP request envelope structure.
    // PeerDeliverArgs wire format: { accountId, message: { id, chatId, senderUserId, ... } }.
    #[test]
    fn build_peer_deliver_request_structure() {
        let sender = "uid:bob@example.com";
        let body = "hey there";
        let chat_id = "b3d4e5f6".repeat(8);
        let msg_id = "01JVWXYZ0000000000000000AB";

        let req = build_peer_deliver_request(
            msg_id,
            &chat_id,
            sender,
            body,
            "text/plain",
            "2026-04-18T20:14:00Z",
            None,
            &[],
        );

        // Oracle: RFC 8620 §3.2 — "using" array required.
        let using = req["using"].as_array().expect("using must be array");
        let using_strs: Vec<&str> = using.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(using_strs.contains(&"urn:ietf:params:jmap:core"));
        assert!(using_strs.contains(&"urn:ietf:params:jmap:chat"));

        // Oracle: RFC 8620 §3.2 — methodCalls is an array of invocations.
        let calls = req["methodCalls"]
            .as_array()
            .expect("methodCalls must be array");
        assert_eq!(calls.len(), 1);
        let inv = calls[0].as_array().expect("invocation must be array");
        assert_eq!(inv.len(), 3);
        assert_eq!(inv[0].as_str().unwrap(), "Peer/deliver");

        // Oracle: PeerDeliverArgs shape — top-level must have accountId and message.
        let args = &inv[1];
        assert_eq!(
            args["accountId"].as_str().unwrap(),
            "a-self",
            "accountId must be present at top level"
        );

        // Oracle: DeliverMessageArgs — nested under "message".
        let msg = &args["message"];
        assert_eq!(msg["id"].as_str().unwrap(), msg_id);
        assert_eq!(msg["chatId"].as_str().unwrap(), &chat_id);
        assert_eq!(msg["senderUserId"].as_str().unwrap(), sender);
        assert_eq!(msg["body"].as_str().unwrap(), body);
        assert_eq!(msg["bodyType"].as_str().unwrap(), "text/plain");
        assert!(msg["replyTo"].is_null() || msg.get("replyTo").is_none());

        // Oracle: RFC 8620 §3.2 — call ID is a non-empty string.
        assert!(!inv[2].as_str().unwrap_or("").is_empty());
    }

    // Oracle: new_with_root_cert must not panic when given valid DER from rcgen.
    // The rcgen certificate is the independent oracle (generated by a separate library,
    // not by the code under test).
    #[test]
    fn new_with_root_cert_does_not_panic() {
        install_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["kith.local".to_string()])
            .expect("rcgen must generate a cert");
        let cert_der = cert.cert.der().to_vec();
        // This must not panic; if construction fails the test binary panics, which is the
        // failure signal.
        let _client = PeerHttpClient::new_with_root_cert(&cert_der);
    }

    // Oracle: with replyTo set, the nested message object must include replyTo.
    #[test]
    fn build_peer_deliver_request_with_reply_to() {
        let req = build_peer_deliver_request(
            "01JVWXYZ0000000000000000AB",
            &"b3d4e5f6".repeat(8),
            "uid:bob@example.com",
            "reply body",
            "text/plain",
            "2026-04-18T20:14:00Z",
            Some("01JVWXYZ0000000000000000AA"),
            &[],
        );
        let msg = &req["methodCalls"][0][1]["message"];
        assert_eq!(
            msg["replyTo"].as_str().unwrap(),
            "01JVWXYZ0000000000000000AA"
        );
    }

    // Oracle: attachments slice is serialized into the "attachments" array on the
    // wire message.  Field values come from an independently-constructed Attachment
    // literal, not from the code under test.
    #[test]
    fn build_peer_deliver_request_with_attachments() {
        use kith_core::Attachment;
        let attachment = Attachment {
            blob_id: "a".repeat(64),
            filename: "test.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 42,
            sha256: "b".repeat(64),
        };
        let req = build_peer_deliver_request(
            "01JVWXYZ0000000000000000AB",
            &"b3d4e5f6".repeat(8),
            "uid:alice@example.com",
            "hello",
            "text/plain",
            "2026-04-18T20:14:00Z",
            None,
            &[attachment],
        );
        let msg = &req["methodCalls"][0][1]["message"];
        let attachments = msg["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0]["blobId"], "a".repeat(64));
        assert_eq!(attachments[0]["filename"], "test.txt");
        assert_eq!(attachments[0]["contentType"], "text/plain");
        assert_eq!(attachments[0]["size"], 42);
        assert_eq!(attachments[0]["sha256"], "b".repeat(64));
    }

    // Oracle: empty attachments slice serializes to an empty JSON array.
    #[test]
    fn build_peer_deliver_request_empty_attachments() {
        let req = build_peer_deliver_request(
            "01JVWXYZ0000000000000000AB",
            &"b3d4e5f6".repeat(8),
            "uid:alice@example.com",
            "hello",
            "text/plain",
            "2026-04-18T20:14:00Z",
            None,
            &[],
        );
        let attachments = req["methodCalls"][0][1]["message"]["attachments"]
            .as_array()
            .unwrap();
        assert!(attachments.is_empty());
    }

    // ---------------------------------------------------------------------------
    // Helper: build DeliverHandler args with an attachments list and optional participants.
    // Used by the attachment validation and group-chat tests below.
    // ---------------------------------------------------------------------------

    /// Build args JSON for a DeliverHandler call with explicit attachments.
    ///
    /// `chat_id` is provided by the caller so tests can inject specific values.
    fn deliver_args_full(
        identity: &Identity,
        chat_id: &str,
        msg_id: &str,
        attachments: serde_json::Value,
    ) -> serde_json::Value {
        let identity_json = serde_json::to_value(identity).unwrap();
        json!({
            "_caller_identity": identity_json,
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": chat_id,
                "senderUserId": identity.user_id,
                "body": "Hello",
                "bodyType": "text/plain",
                "sentAt": "2026-04-19T12:00:00Z",
                "attachments": attachments,
            }
        })
    }

    /// A single valid attachment JSON object.  All fields pass `validate_attachments`.
    fn valid_attachment_json() -> serde_json::Value {
        json!({
            "blobId": "a".repeat(64),
            "filename": "doc.pdf",
            "contentType": "application/pdf",
            "size": 1024u64,
            "sha256": "f".repeat(64),
        })
    }

    // ---------------------------------------------------------------------------
    // Attachment validation rejection tests (10 tests)
    // Oracle: validate_attachments() rules in this file + defensive input handling
    // rules in CLAUDE.md.  Expected outcomes are derived from the spec, not from
    // running the code.
    // ---------------------------------------------------------------------------

    // Oracle: blob_id containing '..' fails the alphanumeric+_- check.
    #[tokio::test]
    async fn deliver_attachment_invalid_blob_id_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "../etc/passwd",
            "filename": "doc.pdf",
            "contentType": "application/pdf",
            "size": 1024u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("blob_id with ../ must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on invalid blobId"
        );
    }

    // Oracle: empty blob_id fails the non-empty check.
    #[tokio::test]
    async fn deliver_attachment_empty_blob_id_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "",
            "filename": "doc.pdf",
            "contentType": "application/pdf",
            "size": 1024u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("empty blobId must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on empty blobId"
        );
    }

    // Oracle: filename containing '..' triggers path-traversal check.
    #[tokio::test]
    async fn deliver_attachment_unsafe_filename_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "../secret.txt",
            "contentType": "application/pdf",
            "size": 1024u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("filename with ../ must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on unsafe filename"
        );
    }

    // Oracle: empty filename fails the non-empty check.
    #[tokio::test]
    async fn deliver_attachment_empty_filename_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "",
            "contentType": "application/pdf",
            "size": 1024u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("empty filename must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on empty filename"
        );
    }

    // Oracle: content_type with no '/' fails the exactly-one-slash check.
    #[tokio::test]
    async fn deliver_attachment_bad_content_type_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "doc.pdf",
            "contentType": "text",
            "size": 1024u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("content_type without '/' must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on bad contentType"
        );
    }

    // Oracle: valid MIME requires a non-empty type part before the slash;
    // "/plain" has an empty type part and must be rejected.
    #[tokio::test]
    async fn deliver_attachment_degenerate_content_type_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "doc.pdf",
            "contentType": "/plain",
            "size": 1024u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("content_type with empty type part must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on degenerate contentType"
        );
    }

    // Oracle: valid MIME requires a non-empty subtype part after the slash;
    // "text/" has an empty subtype part and must be rejected.
    #[tokio::test]
    async fn deliver_attachment_empty_subtype_content_type_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "doc.txt",
            "contentType": "text/",
            "size": 1024u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("content_type with empty subtype part must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on empty-subtype contentType"
        );
    }

    // Oracle: size = 104_857_601 (1 byte over the 100 MiB cap) fails the size check.
    #[tokio::test]
    async fn deliver_attachment_oversized_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "big.bin",
            "contentType": "application/octet-stream",
            "size": 104_857_601u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("size 1 byte over cap must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on oversized attachment"
        );
    }

    // Oracle: size = 0 fails the non-zero check.
    #[tokio::test]
    async fn deliver_attachment_zero_size_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "empty.bin",
            "contentType": "application/octet-stream",
            "size": 0u64,
            "sha256": "f".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("size=0 must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on zero-size attachment"
        );
    }

    // Oracle: sha256 with uppercase chars fails the lowercase-hex check.
    // "AAAA..." contains uppercase A which is not in '0'..='9' | 'a'..='f'.
    #[tokio::test]
    async fn deliver_attachment_bad_sha256_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "doc.pdf",
            "contentType": "application/pdf",
            "size": 1024u64,
            "sha256": "A".repeat(64),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("uppercase sha256 must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on uppercase sha256"
        );
    }

    // Oracle: sha256 of length 32 (not 64) fails the length check.
    #[tokio::test]
    async fn deliver_attachment_bad_sha256_wrong_length_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let bad_att = json!({
            "blobId": "a".repeat(64),
            "filename": "doc.pdf",
            "contentType": "application/pdf",
            "size": 1024u64,
            "sha256": "a".repeat(32),
        });
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([bad_att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("sha256 with wrong length must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored on wrong-length sha256"
        );
    }

    // Oracle: 21 attachments (one over the MAX_ATTACHMENTS=20 cap) must be rejected.
    #[tokio::test]
    async fn deliver_too_many_attachments_rejected() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        // Build 21 valid attachments; each needs a unique blobId (primary key in DB).
        let atts: Vec<serde_json::Value> = (0..21u8)
            .map(|i| {
                json!({
                    "blobId": format!("{:0>64}", format!("{i:x}")),
                    "filename": format!("file{i}.pdf"),
                    "contentType": "application/pdf",
                    "size": 1024u64,
                    "sha256": "f".repeat(64),
                })
            })
            .collect();
        let args = deliver_args_full(&peer, &chat_id, &msg_id, serde_json::Value::Array(atts));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let err = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect_err("21 attachments must be rejected");
        assert_eq!(err.error_type, "invalidArguments");
        let guard = store.lock().unwrap();
        assert!(
            guard.messages().get(&msg_id).unwrap().is_none(),
            "no message must be stored when too many attachments"
        );
    }

    // ---------------------------------------------------------------------------
    // Attachment acceptance and storage tests
    // ---------------------------------------------------------------------------

    // Oracle: a delivery with 1 valid attachment must store exactly that attachment
    // in the attachments table with the literal field values from the request.
    #[tokio::test]
    async fn deliver_with_attachment_stores_metadata() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let att = valid_attachment_json();
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let result = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect("valid attachment delivery must succeed");
        assert_eq!(result["accepted"], true);
        // Oracle: attachment fields must match the literal values in the request.
        // Look up by receiver-assigned id from response, not sender's msg_id.
        let received_id = result["id"].as_str().expect("id must be in response");
        let guard = store.lock().unwrap();
        let stored = guard
            .attachments()
            .list_by_message(received_id)
            .expect("list_by_message must succeed");
        assert_eq!(stored.len(), 1, "exactly one attachment must be stored");
        let a = &stored[0];
        assert_eq!(a.blob_id, "a".repeat(64));
        assert_eq!(a.filename, "doc.pdf");
        assert_eq!(a.content_type, "application/pdf");
        assert_eq!(a.size, 1024u64);
        assert_eq!(a.sha256, "f".repeat(64));
    }

    // Oracle: a delivery with an empty attachments array must succeed and store no attachments.
    #[tokio::test]
    async fn deliver_with_zero_attachments_accepted() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let result = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect("delivery with empty attachments must succeed");
        assert_eq!(result["accepted"], true);
        let guard = store.lock().unwrap();
        let stored = guard
            .attachments()
            .list_by_message(&msg_id)
            .expect("list_by_message must succeed");
        assert!(stored.is_empty(), "no attachments must be stored");
    }

    // ---------------------------------------------------------------------------
    // Server-assigned chatId tests
    // In the new model chatIds are server-assigned ULIDs/strings; the receiver
    // stores the sender as contact_id and accepts any unknown chatId from that sender.
    // ---------------------------------------------------------------------------

    // Oracle: a new chatId from a valid sender must be accepted and the chat created.
    #[tokio::test]
    async fn deliver_new_chat_id_accepted_and_chat_created() {
        let store = make_store();
        let owner_id = "uid:carol";
        let peer = make_identity("uid:alice");
        let chat_id = "01JX000000000000000000ALICE";
        let msg_id = Ulid::new().to_string();
        let args = deliver_args_full(&peer, chat_id, &msg_id, json!([]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        let result = handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect("delivery with new chatId must succeed");
        assert_eq!(result["accepted"], true);
        // Oracle: chat must exist with contact_id = uid:alice.
        let guard = store.lock().unwrap();
        let chat = guard
            .chats()
            .get(chat_id)
            .expect("chats().get must not error")
            .expect("chat must exist after delivery");
        assert_eq!(
            chat.contact_id.as_deref(),
            Some("uid:alice"),
            "contact_id must be the sender's user_id"
        );
    }

    // Oracle: a second deliver from the same sender into the same chatId is accepted.
    #[tokio::test]
    async fn deliver_same_chat_id_same_sender_accepted() {
        let store = make_store();
        let owner_id = "uid:carol";
        let peer = make_identity("uid:alice");
        let chat_id = "01JX000000000000000000ALICE2";
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());

        // First delivery creates the chat.
        let msg1 = Ulid::new().to_string();
        handler
            .call(
                "Peer/deliver".to_string(),
                "c0".to_string(),
                deliver_args_full(&peer, chat_id, &msg1, json!([])),
            )
            .await
            .expect("first delivery must succeed");

        // Second delivery into same chatId from same sender must also succeed.
        let msg2 = Ulid::new().to_string();
        let result = handler
            .call(
                "Peer/deliver".to_string(),
                "c0".to_string(),
                deliver_args_full(&peer, chat_id, &msg2, json!([])),
            )
            .await
            .expect("second delivery from same sender must succeed");
        assert_eq!(result["accepted"], true);
    }

    // ---------------------------------------------------------------------------
    // Idempotency dedup path tests
    // Oracle: at-most-once delivery guarantee — a retransmitted Peer/deliver with
    // the same sender msg_id must produce exactly one message row, not two.
    // Independent oracle: message count in the DB before/after the second call.
    // ---------------------------------------------------------------------------

    // Oracle: delivering the same message_id twice must return accepted=true on
    // both calls, return the SAME receiver-assigned id and receivedAt on the second
    // call (idempotency), and result in exactly ONE message row in the database.
    #[tokio::test]
    async fn deliver_retransmit_returns_original_id_and_no_duplicate_row() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-alice");
        let chat_id = "01JX000000000000000000IDEM1";
        let sender_msg_id = Ulid::new().to_string();
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());

        // First delivery.
        let first = handler
            .call(
                "Peer/deliver".to_string(),
                "c0".to_string(),
                deliver_args_full(&peer, chat_id, &sender_msg_id, json!([])),
            )
            .await
            .expect("first delivery must succeed");
        let original_id = first["id"]
            .as_str()
            .expect("id must be a string")
            .to_string();
        let original_received_at = first["receivedAt"]
            .as_str()
            .expect("receivedAt must be a string")
            .to_string();
        assert_eq!(first["accepted"], true);

        // Capture the state counter after the first delivery.
        let state_after_first = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().expect("state after first")
        };

        // Second delivery of the exact same sender_msg_id (simulates retransmit).
        let second = handler
            .call(
                "Peer/deliver".to_string(),
                "c0".to_string(),
                deliver_args_full(&peer, chat_id, &sender_msg_id, json!([])),
            )
            .await
            .expect("retransmit must succeed (idempotent)");

        // Oracle: accepted=true on both calls.
        assert_eq!(
            second["accepted"], true,
            "retransmit must return accepted=true"
        );

        // Oracle: second call returns the receiver-assigned id from the FIRST call.
        assert_eq!(
            second["id"].as_str().expect("id must be a string"),
            original_id,
            "retransmit must return the original receiver-assigned id"
        );

        // Oracle: second call returns the same receivedAt.
        assert_eq!(
            second["receivedAt"]
                .as_str()
                .expect("receivedAt must be a string"),
            original_received_at,
            "retransmit must return the original receivedAt"
        );

        // Oracle: state counter must NOT advance on the second call.
        let state_after_second = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().expect("state after second")
        };
        assert_eq!(
            state_after_first, state_after_second,
            "state counter must not advance for a retransmitted message"
        );

        // Oracle: exactly ONE message row exists for this sender_msg_id.
        let guard = store.lock().unwrap();
        let found = guard
            .messages()
            .find_by_sender_msg_id(chat_id, &sender_msg_id)
            .expect("find_by_sender_msg_id must not error")
            .expect("message must exist after both delivers");
        assert_eq!(
            found.id, original_id,
            "the stored row must have the receiver-assigned id from the first delivery"
        );
    }

    // ---------------------------------------------------------------------------
    // State counter advance test
    // ---------------------------------------------------------------------------

    // Oracle: a delivery with one valid attachment advances the message state counter by 1.
    // The counter value before and after are read from the store independently.
    #[tokio::test]
    async fn deliver_with_attachment_state_counter_advances() {
        let store = make_store();
        let owner_id = "uid-owner";
        let peer = make_identity("uid-bob");
        let chat_id = "test-direct-chat-07";
        let msg_id = Ulid::new().to_string();
        let state_before = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().expect("get_state before")
        };
        let att = valid_attachment_json();
        let args = deliver_args_full(&peer, &chat_id, &msg_id, json!([att]));
        let handler = DeliverHandler::new(Arc::clone(&store), owner_id.to_string());
        handler
            .call("Peer/deliver".to_string(), "c0".to_string(), args)
            .await
            .expect("delivery with attachment must succeed");
        let state_after = {
            let guard = store.lock().unwrap();
            guard.messages().get_state().expect("get_state after")
        };
        let parse_counter = |s: &str| -> i64 { s.strip_prefix("s-").unwrap().parse().unwrap() };
        assert_eq!(
            parse_counter(&state_after),
            parse_counter(&state_before) + 1,
            "message state counter must advance by exactly 1 after delivery"
        );
    }

    // Oracle: build_peer_deliver_request produces a JMAP envelope with the correct
    // chatId and senderUserId fields; values are independently-constructed string literals.
    #[test]
    fn build_peer_deliver_request_wire_shape() {
        let req = build_peer_deliver_request(
            "01JVWXYZ0000000000000000AB",
            &"b3d4e5f6".repeat(8),
            "uid:alice@example.com",
            "hello",
            "text/plain",
            "2026-04-18T20:14:00Z",
            None,
            &[],
        );
        let msg = &req["methodCalls"][0][1]["message"];
        assert_eq!(msg["chatId"], "b3d4e5f6".repeat(8));
        assert_eq!(msg["senderUserId"], "uid:alice@example.com");
        assert_eq!(msg["body"], "hello");
        assert!(
            msg.get("participants").is_none(),
            "participants field must not appear in wire format"
        );
    }

    // Oracle: serde default — a JSON payload without "attachments" must deserialize
    // into an empty vec, not an error.
    #[test]
    fn deliver_message_args_deserializes_without_attachments() {
        let json = r#"{
            "accountId": "a-self",
            "message": {
                "id": "01JVWXYZ0000000000000000AB",
                "chatId": "b3d4e5f6b3d4e5f6b3d4e5f6b3d4e5f6b3d4e5f6b3d4e5f6b3d4e5f6b3d4e5f6",
                "senderUserId": "uid:alice@example.com",
                "body": "hello",
                "bodyType": "text/plain",
                "sentAt": "2026-04-18T20:14:00Z"
            }
        }"#;
        let args: PeerDeliverArgs = serde_json::from_str(json).unwrap();
        assert!(args.message.attachments.is_empty());
    }

    // ---------------------------------------------------------------------------
    // outbox_tick tests
    // Oracle: KITH-8my spec + outbox retry algorithm in kith-architecture.md
    // ---------------------------------------------------------------------------

    /// Minimal mock client that records calls and returns a preset sequence.
    struct MockClient {
        results: std::sync::Mutex<std::collections::VecDeque<Result<(), PeerDeliveryError>>>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl MockClient {
        fn succeeds() -> Self {
            Self {
                results: std::sync::Mutex::new(std::iter::once(Ok(())).collect()),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn fails(err: PeerDeliveryError) -> Self {
            Self {
                results: std::sync::Mutex::new(std::iter::once(Err(err)).collect()),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl DeliverClient for MockClient {
        fn deliver_msg<'a>(
            &'a self,
            url: &'a str,
            _request: Value,
        ) -> impl std::future::Future<Output = Result<(), PeerDeliveryError>> + Send + 'a {
            let result = self.results.lock().unwrap().pop_front().unwrap_or(Ok(()));
            self.calls.lock().unwrap().push(url.to_string());
            async move { result }
        }
    }

    fn add_contact_and_enqueue(store: &Arc<Mutex<Store>>, msg_id: &str, now: i64) {
        let guard = store.lock().unwrap();
        // Create a chat and message first.
        guard
            .chats()
            .create("chat-out", "direct", Some("uid-bob"), now)
            .unwrap();
        guard
            .messages()
            .insert(
                msg_id,
                "chat-out",
                "self",
                "hello outbox",
                "text/plain",
                None,
                now,
                &DeliveryState::Pending,
                None,
                msg_id,
            )
            .unwrap();
        // Upsert contact then enqueue.
        guard
            .contacts()
            .upsert(
                "uid-bob",
                "bob@example.com",
                "bob-kith.tail.ts.net",
                None,
                now,
            )
            .unwrap();
        guard
            .outbox()
            .enqueue(msg_id, "uid-bob", "bob-kith.tail.ts.net", now)
            .unwrap();
    }

    // Oracle: successful delivery removes the outbox row and sets delivery_state=Delivered.
    #[tokio::test]
    async fn outbox_tick_success_marks_delivered() {
        let store = make_store();
        let now: i64 = 1000;
        let msg_id = "msg-ob-ok";
        add_contact_and_enqueue(&store, msg_id, now);

        let client = MockClient::succeeds();
        outbox_tick(&store, &client, "uid-owner", now).await;

        assert_eq!(client.call_count(), 1, "deliver must be called once");
        let guard = store.lock().unwrap();
        // Outbox row must be gone.
        assert!(
            guard.outbox().get_by_message(msg_id).unwrap().is_empty(),
            "outbox row must be deleted after successful delivery"
        );
        // Message delivery_state must be Delivered.
        let msg = guard.messages().get(msg_id).unwrap().unwrap();
        assert_eq!(
            msg.delivery_state,
            DeliveryState::Delivered,
            "delivery_state must be Delivered after success"
        );
    }

    // Oracle: blocked contact → record_failure called, deliver NOT called.
    #[tokio::test]
    async fn outbox_tick_blocked_contact_records_failure_no_deliver() {
        let store = make_store();
        let now: i64 = 1000;
        let msg_id = "msg-ob-blocked";
        add_contact_and_enqueue(&store, msg_id, now);

        // Block the contact after enqueue.
        store
            .lock()
            .unwrap()
            .contacts()
            .set_blocked("uid-bob", true)
            .unwrap();

        let client = MockClient::succeeds();
        outbox_tick(&store, &client, "uid-owner", now).await;

        assert_eq!(
            client.call_count(),
            0,
            "deliver must NOT be called for blocked contact"
        );
        // Outbox row must still exist with attempt_count incremented.
        let entries = store
            .lock()
            .unwrap()
            .outbox()
            .get_by_message(msg_id)
            .unwrap();
        assert!(
            !entries.is_empty(),
            "outbox row must remain after blocked failure"
        );
        assert_eq!(
            entries[0].attempt_count, 1,
            "attempt_count must be incremented"
        );
    }

    // Oracle: network error → record_failure; next_attempt_at respects backoff.
    // Spec: attempt_count=0 → delay=60s.
    #[tokio::test]
    async fn outbox_tick_network_error_records_failure_with_backoff() {
        let store = make_store();
        let now: i64 = 5000;
        let msg_id = "msg-ob-neterr";
        add_contact_and_enqueue(&store, msg_id, now);

        let client = MockClient::fails(PeerDeliveryError::Network("conn refused".into()));
        outbox_tick(&store, &client, "uid-owner", now).await;

        assert_eq!(client.call_count(), 1, "deliver must be attempted");
        let entries = store
            .lock()
            .unwrap()
            .outbox()
            .get_by_message(msg_id)
            .unwrap();
        assert!(
            !entries.is_empty(),
            "outbox row must remain after network error"
        );
        let entry = &entries[0];
        assert_eq!(entry.attempt_count, 1);
        // Oracle: first failure (attempt_count was 0) → base = 30s, ±20% jitter → [24, 36].
        assert!(
            entry.next_attempt_at >= now + 24 && entry.next_attempt_at <= now + 36,
            "first failure: next_attempt_at must be in [now+24, now+36], got {}",
            entry.next_attempt_at
        );
    }

    // Oracle: 72nd failure → mark_failed; message.delivery_state = Failed.
    // Spec: 72 max attempts (KITH-vhv). Attempt 71 must NOT yet mark_failed.
    #[tokio::test]
    async fn outbox_tick_seventy_second_failure_marks_message_failed() {
        let store = make_store();
        let mut now: i64 = 1000;
        let msg_id = "msg-ob-72nd";
        add_contact_and_enqueue(&store, msg_id, now);

        // Drive 72 failure ticks.  Each tick: client fails → record_failure called.
        // Advance by 5000s per tick: greater than the maximum possible delay
        // (3600s base × 1.2 jitter = 4320s), ensuring get_due always returns the entry.
        for _ in 0..72 {
            let client = MockClient::fails(PeerDeliveryError::Timeout);
            outbox_tick(&store, &client, "uid-owner", now).await;
            now += 5000;
        }

        // Outbox row must be deleted after the 72nd failure (mark_failed).
        let entries = store
            .lock()
            .unwrap()
            .outbox()
            .get_by_message(msg_id)
            .unwrap();
        assert!(
            entries.is_empty(),
            "outbox row must be deleted after 72 failures"
        );

        // Oracle: message.delivery_state must be Failed.
        let msg = store
            .lock()
            .unwrap()
            .messages()
            .get(msg_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            msg.delivery_state,
            DeliveryState::Failed,
            "delivery_state must be Failed after 72 failures"
        );
    }

    // Oracle: outbox_tick with no due entries makes no deliver calls.
    #[tokio::test]
    async fn outbox_tick_no_due_entries_no_deliver() {
        let store = make_store();
        let now: i64 = 1000;
        let msg_id = "msg-ob-future";
        add_contact_and_enqueue(&store, msg_id, now + 9999); // due in the future

        let client = MockClient::succeeds();
        outbox_tick(&store, &client, "uid-owner", now).await;

        assert_eq!(
            client.call_count(),
            0,
            "no deliver call when nothing is due"
        );
    }

    /// A mock deliver client that captures the first request payload it receives.
    struct CapturingMockClient {
        captured: std::sync::Mutex<Option<Value>>,
    }

    impl CapturingMockClient {
        fn new() -> Self {
            Self {
                captured: std::sync::Mutex::new(None),
            }
        }

        fn take(&self) -> Option<Value> {
            self.captured.lock().unwrap().take()
        }
    }

    impl DeliverClient for CapturingMockClient {
        fn deliver_msg<'a>(
            &'a self,
            _url: &'a str,
            request: Value,
        ) -> impl std::future::Future<Output = Result<(), PeerDeliveryError>> + Send + 'a {
            *self.captured.lock().unwrap() = Some(request);
            async move { Ok(()) }
        }
    }

    // Oracle: the attachment stored in the DB is exactly what appears on the wire.
    // Expected blobId/filename/etc. are the literal strings inserted into the store —
    // independent of the serialization path under test.
    #[tokio::test]
    async fn outbox_tick_sends_attachments_in_wire_format() {
        let store = make_store();
        let now: i64 = 1000;
        let msg_id = "msg-ob-att";

        // Set up chat, message, contact, and outbox entry (uses chat-out / uid-bob).
        add_contact_and_enqueue(&store, msg_id, now);

        // Insert one attachment row for this message.
        {
            let guard = store.lock().unwrap();
            guard
                .attachments()
                .insert(
                    &"a".repeat(64), // blob_id — oracle value
                    msg_id,
                    "doc.txt",
                    "text/plain",
                    10,
                    &"b".repeat(64), // sha256 — oracle value
                    now,
                )
                .expect("insert attachment");
        }

        let client = CapturingMockClient::new();
        outbox_tick(&store, &client, "uid-owner", now).await;

        let req = client.take().expect("deliver_msg must have been called");
        let msg = &req["methodCalls"][0][1]["message"];
        let attachments = msg["attachments"]
            .as_array()
            .expect("attachments must be an array");
        assert_eq!(attachments.len(), 1, "exactly one attachment on the wire");
        // Oracle: values match the literals inserted above.
        assert_eq!(attachments[0]["blobId"], "a".repeat(64));
        assert_eq!(attachments[0]["filename"], "doc.txt");
        assert_eq!(attachments[0]["contentType"], "text/plain");
        assert_eq!(attachments[0]["size"], 10);
        assert_eq!(attachments[0]["sha256"], "b".repeat(64));
    }

    // Oracle: outbox_tick serializes the stored chatId and senderUserId onto the wire.
    // Values are the literal strings inserted into the store at setup time.
    #[tokio::test]
    async fn outbox_tick_sends_chat_id_and_sender_in_wire_format() {
        let store = make_store();
        let now: i64 = 2000;
        let msg_id = "msg-ob-part";
        let chat_id = "chat-ob-wire-01";

        // Insert a chat, message, contact, and outbox entry.
        {
            let guard = store.lock().unwrap();
            guard
                .chats()
                .create(chat_id, "direct", Some("uid-bob"), now)
                .expect("create chat");
            guard
                .messages()
                .insert(
                    msg_id,
                    chat_id,
                    "self",
                    "hello wire format",
                    "text/plain",
                    None,
                    now,
                    &DeliveryState::Pending,
                    None,
                    msg_id,
                )
                .expect("insert message");
            guard
                .contacts()
                .upsert(
                    "uid-bob",
                    "bob@example.com",
                    "bob-kith.tail.ts.net",
                    None,
                    now,
                )
                .expect("upsert contact");
            guard
                .outbox()
                .enqueue(msg_id, "uid-bob", "bob-kith.tail.ts.net", now)
                .expect("enqueue");
        }

        let client = CapturingMockClient::new();
        outbox_tick(&store, &client, "uid-owner", now).await;

        let req = client.take().expect("deliver_msg must have been called");
        let wire_msg = &req["methodCalls"][0][1]["message"];
        // Oracle: chatId on the wire must match the stored chat_id literal.
        assert_eq!(
            wire_msg["chatId"], chat_id,
            "chatId must match the stored value"
        );
        // Oracle: senderUserId on the wire must be the owner (outbox sends as owner).
        assert_eq!(
            wire_msg["senderUserId"], "uid-owner",
            "senderUserId must be the owner"
        );
    }

    // Oracle: shape is derived from the Peer/receipt wire format spec in kith-architecture.md.
    #[test]
    fn build_peer_receipt_request_json_shape() {
        let req = build_peer_receipt_request(
            "01JVWXYZ0000000000000000AB",
            "read",
            "2026-04-19T12:00:00Z",
        );
        assert_eq!(req["using"][0], "urn:ietf:params:jmap:core");
        assert_eq!(req["methodCalls"][0][0], "Peer/receipt");
        let args = &req["methodCalls"][0][1];
        assert_eq!(args["accountId"], "a-self");
        assert_eq!(args["messageId"], "01JVWXYZ0000000000000000AB");
        assert_eq!(args["kind"], "read");
        assert_eq!(args["at"], "2026-04-19T12:00:00Z");
        assert_eq!(req["methodCalls"][0][2], "0");
    }
}
