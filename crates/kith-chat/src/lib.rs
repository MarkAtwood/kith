pub mod chat;
pub mod contact;
pub mod message;
pub mod permission;
pub mod space;

pub(crate) fn kith_to_jmap(e: kith_core::KithError) -> kith_core::JmapError {
    match e {
        kith_core::KithError::Validation(msg) => kith_core::JmapError::invalid_arguments(msg),
        kith_core::KithError::Jmap(e) => e,
        other => {
            tracing::error!("store error: {other}");
            kith_core::JmapError::server_fail("internal error")
        }
    }
}
