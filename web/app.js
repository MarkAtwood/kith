// Kith web client

// ---------------------------------------------------------------------------
// Module state — populated by bootstrap()
// ---------------------------------------------------------------------------

const session = {
  apiUrl: null,
  eventsUrl: null,
  uploadUrl: null,
  downloadUrl: null,
  accountId: 'a-self',
  username: null,
};

// contacts: Map<id, contact> — populated by fetchContacts()
const contacts = new Map();

// chats: Map<id, chat> — populated by fetchChats()
const chats = new Map();

// chatState: opaque state token from last Chat/get, for Chat/changes
let chatState = null;

// contactState: opaque state token from last Contact/get, for Contact/changes
let contactState = null;

// messageState: opaque state token from last Message/get, for Message/changes
let messageState = null;

// currentChatId: id of the currently displayed chat, or null
let currentChatId = null;

// pendingAttachments: attachments selected but not yet sent.
// Each entry: {blobId, filename, contentType, size, sha256}
let pendingAttachments = [];

// uploadsInProgress: count of active uploadBlob calls. Send is blocked while > 0.
let uploadsInProgress = 0;

// ---------------------------------------------------------------------------
// JMAP helpers
// ---------------------------------------------------------------------------

/**
 * Call one or more JMAP methods in a single request.
 * @param {Array} methodCalls - array of [methodName, args, callId] triples
 * @returns {Array} methodResponses array from the server
 */
export async function callJmap(methodCalls) {
  if (!session.apiUrl) throw new Error('session not initialized');
  const resp = await fetch(session.apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      using: ['urn:ietf:params:jmap:core', 'urn:kith:chat:1'],
      methodCalls,
    }),
  });
  if (!resp.ok) throw new Error(`JMAP API error: HTTP ${resp.status}`);
  const data = await resp.json();
  return data.methodResponses;
}

/**
 * Build the EventSource URL from the session template.
 * Replaces {types}, {closeafter}, and {ping} placeholders.
 * @param {string} types - comma-separated type names e.g. 'Message,Chat'
 * @returns {string} resolved URL
 */
export function buildEventsUrl(types) {
  return (session.eventsUrl || '')
    .replace('{types}', encodeURIComponent(types))
    .replace('{closeafter}', 'no')
    .replace('{ping}', '');
}

// ---------------------------------------------------------------------------
// Blob helpers
// ---------------------------------------------------------------------------

/**
 * Format a byte count as a human-readable string.
 * @param {number} n - byte count
 * @returns {string}
 */
export function formatBytes(n) {
  if (n >= 1_048_576) return `${(n / 1_048_576).toFixed(1)} MB`;
  if (n >= 1_024) return `${(n / 1_024).toFixed(1)} KB`;
  return `${n} B`;
}

/**
 * Upload a File object to the kithd blob endpoint.
 * Returns attachment metadata including the server-assigned blobId.
 * The original filename is preserved from file.name since the server
 * does not return it in the response.
 * @param {File} file
 * @returns {Promise<{blobId: string, filename: string, contentType: string, size: number, sha256: string}>}
 */
export async function uploadBlob(file) {
  const uploadUrl = session.uploadUrl.replace('{accountId}', 'a-self');
  const resp = await fetch(uploadUrl, {
    method: 'POST',
    headers: { 'Content-Type': file.type || 'application/octet-stream' },
    body: file,
  });
  if (!resp.ok) {
    if (resp.status === 413) throw new Error('File too large (max 100 MB)');
    throw new Error(`Upload failed: HTTP ${resp.status}`);
  }
  const { blobId, size, type, sha256 } = await resp.json();
  return { blobId, filename: file.name, contentType: type, size, sha256 };
}

/**
 * Build a DOM element for a single attachment (download link + file size).
 * Uses textContent throughout — never innerHTML — to prevent XSS.
 * att.filename, att.contentType come from peer-supplied message data
 * and must never be inserted as HTML.
 * @param {{blobId: string, filename: string, contentType: string, size: number}} att
 * @returns {HTMLElement}
 */
export function buildAttachmentElement(att) {
  const container = document.createElement('div');
  container.className = 'attachment-link';

  // Construct download URL from the session template.
  // Each variable is URL-encoded to prevent injection into the URL path.
  const downloadUrl = (session.downloadUrl || '')
    .replace('{accountId}', encodeURIComponent('a-self'))
    .replace('{blobId}', encodeURIComponent(att.blobId))
    .replace('{name}', encodeURIComponent(att.filename))
    .replace('{type}', encodeURIComponent(att.contentType));

  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = att.filename;      // forces save-as dialog
  a.textContent = att.filename;   // CRITICAL: textContent not innerHTML

  const sz = document.createElement('span');
  sz.className = 'attachment-size';
  sz.textContent = formatBytes(att.size); // textContent — safe

  container.appendChild(a);
  container.appendChild(sz);
  return container;
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/**
 * Fetch the JMAP session from /.well-known/jmap and populate module state.
 * Shows the error banner and throws on failure.
 */
export async function bootstrap() {
  try {
    const resp = await fetch('/.well-known/jmap');
    if (!resp.ok) throw new Error(`Session fetch failed: HTTP ${resp.status}`);
    const data = await resp.json();
    session.apiUrl = data.apiUrl;
    session.eventsUrl = data.eventSourceUrl;
    session.uploadUrl = data.uploadUrl;
    session.downloadUrl = data.downloadUrl;
    session.username = data.username;
    // accountId is always 'a-self'; confirm from primaryAccounts if present
    if (data.primaryAccounts && data.primaryAccounts['urn:kith:chat:1']) {
      session.accountId = data.primaryAccounts['urn:kith:chat:1'];
    }
  } catch (err) {
    showError('Cannot connect to Kith. Is Tailscale running on this device? (' + err.message + ')');
    throw err;
  }
  return session;
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

/**
 * Show the error banner with the given message.
 * @param {string} msg
 */
export function showError(msg) {
  const banner = document.getElementById('error-banner');
  if (!banner) return;
  banner.textContent = msg;
  banner.classList.add('visible');
}

/**
 * Hide the error banner.
 */
export function hideError() {
  const banner = document.getElementById('error-banner');
  if (!banner) return;
  banner.textContent = '';
  banner.classList.remove('visible');
}

// ---------------------------------------------------------------------------
// Contact helpers
// ---------------------------------------------------------------------------

/**
 * Return the best available display name for a contact.
 * Falls back from displayName → login → tailscaleUserId.
 * @param {Object} contact
 * @returns {string}
 */
export function getContactName(contact) {
  if (contact.displayName && contact.displayName.trim().length > 0) {
    return contact.displayName.trim();
  }
  if (contact.login && contact.login.trim().length > 0) {
    return contact.login.trim();
  }
  return contact.tailscaleUserId;
}

/**
 * Fetch all contacts from the server and populate the contacts Map.
 * @returns {Array} list of contact objects
 */
export async function fetchContacts() {
  const responses = await callJmap([
    ['Contact/get', { accountId: session.accountId, ids: null }, 'c0'],
  ]);
  const [, result] = responses[0];
  if (result.type) throw new Error('Contact/get error: ' + result.type);
  for (const c of result.list) {
    contacts.set(c.id, c);
  }
  contactState = result.state;
  return result.list;
}

/**
 * Render the contact list into #contact-list.
 * Shows all contacts including blocked ones; blocked contacts are visually dimmed.
 * Uses textContent throughout — never innerHTML for user data.
 * @param {Array} contactList
 */
export function renderContactList(contactList) {
  const ul = document.getElementById('contact-list');
  if (!ul) { console.error('Kith: #contact-list element not found'); return; }
  ul.textContent = '';
  for (const contact of contactList) {
    const li = document.createElement('li');
    li.className = 'contact-item' + (contact.blocked ? ' blocked' : '');
    li.dataset.contactId = contact.id;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'contact-name';
    nameSpan.textContent = getContactName(contact); // textContent — XSS safe

    const blockBtn = document.createElement('button');
    blockBtn.className = 'block-btn';
    blockBtn.type = 'button';
    blockBtn.textContent = contact.blocked ? 'Unblock' : 'Block';
    blockBtn.title = contact.blocked ? 'Unblock this contact' : 'Block this contact';

    blockBtn.addEventListener('click', async (e) => {
      e.stopPropagation(); // prevent chat open
      blockBtn.disabled = true;
      const ok = await setContactBlocked(contact.id, !contact.blocked);
      if (!ok) blockBtn.disabled = false;
      // setContactBlocked calls renderContactList on success, so button is rebuilt
    });

    li.appendChild(nameSpan);
    li.appendChild(blockBtn);

    // Click on the row (not button) opens the chat
    li.addEventListener('click', () => {
      if (contact.blocked) {
        showError('Contact is blocked — unblock to send messages');
        return;
      }
      openOrCreateChat(contact);
    });

    ul.appendChild(li);
  }
}

/**
 * Block or unblock a contact via Contact/set update.
 * Updates the local contacts Map and re-renders the contact list.
 * @param {string} contactId - The contact's tailscaleUserId
 * @param {boolean} blocked - true to block, false to unblock
 * @returns {Promise<boolean>} true on success, false on failure
 */
export async function setContactBlocked(contactId, blocked) {
  if (!contactId) return false;

  let responses;
  try {
    responses = await callJmap([
      ['Contact/set', {
        accountId: session.accountId,
        update: { [contactId]: { blocked } },
      }, 'm0'],
    ]);
  } catch (err) {
    showError('Could not update contact: ' + err.message);
    return false;
  }

  const [, result] = responses[0];

  if (result.notUpdated && result.notUpdated[contactId]) {
    const err = result.notUpdated[contactId];
    showError('Could not update contact: ' + err.type + (err.description ? ': ' + err.description : ''));
    return false;
  }

  // Update local state
  const contact = contacts.get(contactId);
  if (contact) {
    contacts.set(contactId, { ...contact, blocked });
    renderContactList([...contacts.values()]);
  }

  return true;
}

/**
 * Open an existing direct chat with contact, or create a new one.
 * Full chat rendering is implemented in bead g7q; selectChat is a stub here.
 * @param {Object} contact
 */
export async function openOrCreateChat(contact) {
  // Look for existing direct chat with this contact
  // chats Map is populated by fetchChats() in bead g7q; for now stub it
  const existing = [...(typeof chats !== 'undefined' ? chats.values() : [])].find(
    (ch) => ch.participants && ch.participants.includes(contact.id)
  );
  if (existing) {
    selectChat(existing.id);
    return;
  }
  // Create a new chat
  try {
    const responses = await callJmap([
      ['Chat/set', { accountId: session.accountId, create: { c0: { contactId: contact.id } } }, 'cs0'],
    ]);
    const [, result] = responses[0];
    if (result.type) {
      showError('Could not start chat: ' + result.type);
      return;
    }
    if (result.notCreated && result.notCreated.c0) {
      showError('Could not start chat: ' + result.notCreated.c0.description);
      return;
    }
    const newChat = result.created.c0;
    selectChat(newChat.id);
  } catch (err) {
    showError('Could not start chat: ' + err.message);
  }
}

// ---------------------------------------------------------------------------
// Chat helpers
// ---------------------------------------------------------------------------

/**
 * Fetch all chats from the server and populate the chats Map.
 * Uses Chat/query + Chat/get chained via ResultReference (RFC 8620 §9).
 * @returns {Array} list of chat objects in query order (server sorts by lastMessageAt desc)
 */
export async function fetchChats() {
  const responses = await callJmap([
    ['Chat/query', { accountId: session.accountId, calculateTotal: false }, 'q0'],
    ['Chat/get', {
      accountId: session.accountId,
      '#ids': { resultOf: 'q0', name: 'Chat/query', path: '/ids' },
    }, 'g0'],
  ]);
  const [, queryResult] = responses[0];
  const [, getResult] = responses[1];
  if (queryResult.type) throw new Error('Chat/query error: ' + queryResult.type);
  if (getResult.type) throw new Error('Chat/get error: ' + getResult.type);
  chats.clear();
  for (const ch of getResult.list) {
    chats.set(ch.id, ch);
  }
  chatState = getResult.state;
  // Return in query order (server sorts by lastMessageAt desc)
  return queryResult.ids.map((id) => chats.get(id)).filter(Boolean);
}

/**
 * Return a display name for a chat, derived from its participants list.
 * Falls back to the first 8 chars of the chat ID if participants is empty.
 * @param {Object} chat
 * @returns {string}
 */
export function getChatDisplayName(chat) {
  if (!chat.participants || chat.participants.length === 0) {
    return chat.id.slice(0, 8); // fallback to partial id
  }
  const contact = contacts.get(chat.participants[0]);
  return contact ? getContactName(contact) : chat.participants[0];
}

/**
 * Render the chat list into #chat-list.
 * Uses textContent throughout — never innerHTML for user data.
 * @param {Array} chatList
 */
export function renderChatList(chatList) {
  const ul = document.getElementById('chat-list');
  if (!ul) { console.error('Kith: #chat-list element not found'); return; }
  ul.textContent = '';
  for (const chat of chatList) {
    const li = document.createElement('li');
    li.className = 'chat-item' + (chat.id === currentChatId ? ' active' : '');
    li.dataset.chatId = chat.id;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'chat-name';
    nameSpan.textContent = getChatDisplayName(chat); // textContent — XSS safe

    li.appendChild(nameSpan);

    if (chat.unreadCount && chat.unreadCount > 0) {
      const badge = document.createElement('span');
      badge.className = 'unread-badge';
      badge.textContent = String(chat.unreadCount);
      li.appendChild(badge);
    }

    li.addEventListener('click', () => selectChat(chat.id));
    ul.appendChild(li);
  }
}

/**
 * Select the given chat, updating the active highlight in the chat list.
 * Message thread loading is added by bead be1.
 * @param {string} chatId
 */
export function selectChat(chatId) {
  currentChatId = chatId;
  // Update active state in chat list
  document.querySelectorAll('.chat-item').forEach((el) => {
    el.classList.toggle('active', el.dataset.chatId === chatId);
  });
  // Message thread loading is added by bead be1
  if (typeof fetchMessages === 'function') {
    fetchMessages(chatId).catch((err) => showError('Failed to load messages: ' + err.message));
  }
}

// ---------------------------------------------------------------------------
// Message helpers
// ---------------------------------------------------------------------------

/**
 * Fetch messages for a chat using Message/query + Message/get via ResultReference.
 * Populates messageState and renders the thread.
 * @param {string} chatId
 * @returns {Array} list of message objects in query order (oldest first)
 */
export async function fetchMessages(chatId) {
  const responses = await callJmap([
    ['Message/query', {
      accountId: session.accountId,
      filter: { chatId },
      calculateTotal: false,
    }, 'q0'],
    ['Message/get', {
      accountId: session.accountId,
      '#ids': { resultOf: 'q0', name: 'Message/query', path: '/ids' },
    }, 'g0'],
  ]);
  const [, queryResult] = responses[0];
  const [, getResult] = responses[1];
  if (queryResult.type) throw new Error('Message/query error: ' + queryResult.type);
  if (getResult.type) throw new Error('Message/get error: ' + getResult.type);
  messageState = getResult.state;
  // Return in query order (server returns oldest-first for message threads)
  const messageMap = new Map(getResult.list.map((m) => [m.id, m]));
  const messages = queryResult.ids.map((id) => messageMap.get(id)).filter(Boolean);
  renderThread(messages);
  return messages;
}

/**
 * Return a display label for the sender of a message.
 * Returns 'Me' for the owner's messages, or the contact name for peer messages.
 * Falls back to the raw senderId if the contact is not found.
 * @param {Object} msg
 * @returns {string}
 */
export function getSenderLabel(msg) {
  if (msg.senderId === 'self') return 'Me';
  const contact = contacts.get(msg.senderId);
  return contact ? getContactName(contact) : msg.senderId;
}

/**
 * Create a DOM element for a single message bubble.
 * Uses textContent throughout — never innerHTML — to prevent XSS.
 * Uses receivedAt for the timestamp (sentAt is peer-supplied and untrusted).
 * @param {Object} msg
 * @returns {HTMLElement}
 */
export function createMessageBubble(msg) {
  const isSelf = msg.senderId === 'self';
  const wrapper = document.createElement('div');
  wrapper.className = 'message ' + (isSelf ? 'self' : 'peer');
  wrapper.dataset.messageId = msg.id;

  const body = document.createElement('p');
  body.textContent = msg.body; // CRITICAL: textContent not innerHTML — prevents XSS

  const meta = document.createElement('div');
  meta.className = 'message-meta';
  const ts = new Date(msg.receivedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  meta.textContent = getSenderLabel(msg) + ' · ' + ts; // textContent — safe

  wrapper.appendChild(body);
  wrapper.appendChild(meta);
  if (Array.isArray(msg.attachments) && msg.attachments.length > 0) {
    const attDiv = document.createElement('div');
    attDiv.className = 'message-attachments';
    for (const att of msg.attachments) {
      attDiv.appendChild(buildAttachmentElement(att));
    }
    wrapper.appendChild(attDiv);
  }
  return wrapper;
}

/**
 * Render the full message thread into #message-thread, replacing its contents.
 * Scrolls to the bottom after rendering.
 * @param {Array} messages
 */
export function renderThread(messages) {
  const div = document.getElementById('message-thread');
  if (!div) { console.error('Kith: #message-thread element not found'); return; }
  div.textContent = '';
  for (const msg of messages) {
    div.appendChild(createMessageBubble(msg));
  }
  div.scrollTop = div.scrollHeight; // scroll to bottom
}

/**
 * Append a single message bubble to the thread and scroll to bottom.
 * Used by compose and EventSource push handlers.
 * @param {Object} msg
 */
export function appendMessageBubble(msg) {
  const div = document.getElementById('message-thread');
  if (!div) { console.error('Kith: #message-thread element not found'); return; }
  div.appendChild(createMessageBubble(msg));
  div.scrollTop = div.scrollHeight;
}

// ---------------------------------------------------------------------------
// Compose helpers
// ---------------------------------------------------------------------------

/**
 * Re-render the attachment preview strip below the compose textarea.
 * Uses textContent for all user-supplied data — never innerHTML.
 */
function renderAttachmentPreview() {
  const previewDiv = document.getElementById('attachment-preview');
  if (!previewDiv) { console.error('Kith: #attachment-preview element not found'); return; }
  previewDiv.textContent = ''; // clears all children safely
  for (const att of pendingAttachments) {
    const item = document.createElement('div');
    item.className = 'attachment-preview-item';

    const nameSpan = document.createElement('span');
    nameSpan.textContent = att.filename; // textContent — XSS safe

    const sizeSpan = document.createElement('span');
    sizeSpan.textContent = ' (' + formatBytes(att.size) + ')';

    const removeBtn = document.createElement('button');
    removeBtn.className = 'remove-btn';
    removeBtn.type = 'button';
    removeBtn.textContent = '✕';
    removeBtn.addEventListener('click', () => {
      const idx = pendingAttachments.indexOf(att);
      if (idx !== -1) pendingAttachments.splice(idx, 1);
      renderAttachmentPreview();
    });

    item.appendChild(nameSpan);
    item.appendChild(sizeSpan);
    item.appendChild(removeBtn);
    previewDiv.appendChild(item);
  }
}

/**
 * Wire up the compose textarea and send button.
 * Must be called after the DOM is ready; called by renderApp after renderChatList.
 */
export function setupCompose() {
  const btn = document.getElementById('send-btn');
  const textarea = document.getElementById('compose-body');
  if (!btn || !textarea) { console.error('Kith: #send-btn or #compose-body element not found'); return; }

  btn.addEventListener('click', sendMessage);

  textarea.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  // Auto-resize textarea as user types
  textarea.addEventListener('input', () => {
    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
  });

  const attachBtn = document.getElementById('attach-btn');
  const fileInput = document.getElementById('file-input');
  if (!attachBtn || !fileInput) {
    console.error('Kith: #attach-btn or #file-input element not found');
    return;
  }

  attachBtn.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', async (e) => {
    const sendBtn = document.getElementById('send-btn');
    uploadsInProgress += e.target.files.length;
    if (sendBtn) sendBtn.disabled = true;
    for (const file of Array.from(e.target.files)) {
      try {
        const result = await uploadBlob(file);
        pendingAttachments.push(result);
      } catch (err) {
        showError('Attachment upload failed: ' + err.message);
      } finally {
        uploadsInProgress -= 1;
      }
    }
    fileInput.value = ''; // reset so same file can be re-selected
    if (sendBtn && uploadsInProgress === 0) sendBtn.disabled = false;
    renderAttachmentPreview();
  });
}

/**
 * Read the compose textarea, send a Message/set create request,
 * show an optimistic bubble immediately, then replace it with the
 * real server response (or revert on failure).
 */
async function sendMessage() {
  const textarea = document.getElementById('compose-body');
  if (!textarea) return;
  const body = textarea.value.trim();
  if (!body || !currentChatId) return;
  if (uploadsInProgress > 0) {
    showError('Please wait for attachment upload to finish');
    return;
  }

  const attachmentsSnapshot = pendingAttachments.slice();

  // Clear the textarea immediately
  textarea.value = '';
  textarea.style.height = 'auto';
  pendingAttachments = pendingAttachments.filter(a => !attachmentsSnapshot.includes(a));
  renderAttachmentPreview();

  const sendBtn = document.getElementById('send-btn');
  if (sendBtn) sendBtn.disabled = true;

  // Optimistic UI: show the message immediately with a temp id
  const tempId = 'temp-' + Date.now();
  const optimistic = {
    id: tempId,
    chatId: currentChatId,
    senderId: 'self',
    body,
    bodyType: 'text/plain',
    receivedAt: new Date().toISOString(),
    deliveryState: 'pending',
    attachments: attachmentsSnapshot,
  };
  appendMessageBubble(optimistic);

  try {
    try {
      const responses = await callJmap([
        ['Message/set', {
          accountId: session.accountId,
          create: {
            c0: {
              chatId: currentChatId,
              body,
              bodyType: 'text/plain',
              sentAt: new Date().toISOString(),
              attachments: attachmentsSnapshot.map(a => ({
                blobId: a.blobId,
                filename: a.filename,
                contentType: a.contentType,
                size: a.size,
                sha256: a.sha256,
              })),
            },
          },
        }, 's0'],
      ]);
      const [, result] = responses[0];

      if (result.type) {
        throw new Error('Message/set error: ' + result.type);
      }
      if (result.notCreated && result.notCreated.c0) {
        throw new Error(result.notCreated.c0.description || 'Message/set failed');
      }

      // Replace optimistic bubble with real message
      const created = result.created && result.created.c0;
      if (created) {
        const tempEl = document.querySelector(`[data-message-id="${tempId}"]`);
        if (tempEl) {
          const realBubble = createMessageBubble(created);
          tempEl.replaceWith(realBubble);
        }
      }
    } catch (err) {
      // Revert: remove optimistic bubble and restore textarea
      const tempEl = document.querySelector(`[data-message-id="${tempId}"]`);
      if (tempEl) tempEl.remove();
      textarea.value = body;
      pendingAttachments = attachmentsSnapshot;
      renderAttachmentPreview();
      showError('Send failed: ' + err.message);
    }
  } finally {
    if (sendBtn) sendBtn.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// EventSource subscription
// ---------------------------------------------------------------------------

let eventsource = null;

export function startEventSource() {
  if (eventsource) {
    eventsource.close();
  }
  const url = buildEventsUrl('Message,Chat,Contact');
  eventsource = new EventSource(url);

  eventsource.addEventListener('state', handleStateEvent);

  eventsource.onerror = () => {
    // Browser reconnects automatically; log but do not crash
    console.warn('Kith EventSource: connection lost, will reconnect');
  };
}

async function handleStateEvent(event) {
  let data;
  try {
    data = JSON.parse(event.data);
  } catch (err) {
    console.error('Kith EventSource: failed to parse event data', err);
    return;
  }

  const changed = data.changed && data.changed[session.accountId];
  if (!changed) return;

  const methodCalls = [];
  if (changed.Message && messageState === null) {
    // No baseline yet (no chat selected): sync the state token so the next
    // /changes call starts from the right point. Skip Message/changes this
    // cycle — there is no prior state to diff against.
    messageState = changed.Message;
  } else if (changed.Message) {
    methodCalls.push(['Message/changes', { accountId: session.accountId, sinceState: messageState }, 'mc0']);
  }
  if (changed.Chat && chatState === null) {
    // Sync baseline; skip Chat/changes this cycle — no prior state to diff against
    chatState = changed.Chat;
  } else if (changed.Chat) {
    methodCalls.push(['Chat/changes', { accountId: session.accountId, sinceState: chatState }, 'cc0']);
  }

  if (methodCalls.length === 0) return;

  try {
    const responses = await callJmap(methodCalls);

    for (const [methodName, result] of responses) {
      if (methodName === 'Message/changes') {
        if (result.type === 'cannotCalculateChanges') {
          // State gap — re-fetch all messages for current chat
          if (currentChatId) {
            await fetchMessages(currentChatId);
          }
          continue;
        }
        if (result.type) {
          // Other server error — sync token from event data to avoid retrying with bad state
          console.error('Kith: Message/changes error:', result.type);
          if (changed.Message) messageState = changed.Message;
          continue;
        }
        messageState = result.newState;
        // Fetch and append new messages for the current chat
        if (result.created && result.created.length > 0 && currentChatId) {
          const getResponses = await callJmap([
            ['Message/get', { accountId: session.accountId, ids: result.created }, 'mg0'],
          ]);
          const [, getResult] = getResponses[0];
          if (!getResult.type) {
            for (const msg of getResult.list) {
              if (msg.chatId === currentChatId) {
                appendMessageBubble(msg);
              }
            }
            // Issue 4 fix: only refresh chat list if new messages arrived in a non-active chat
            const nonActiveChatMessages = getResult.list.filter(m => m.chatId !== currentChatId);
            if (nonActiveChatMessages.length > 0) {
              await refreshChatList();
            }
          }
        }
      } else if (methodName === 'Chat/changes') {
        if (result.type === 'cannotCalculateChanges') {
          await refreshChatList();
          continue;
        }
        if (result.type) {
          console.error('Kith: Chat/changes error:', result.type);
          if (changed.Chat) chatState = changed.Chat;
          continue;
        }
        chatState = result.newState;
        if ((result.created && result.created.length > 0) ||
            (result.updated && result.updated.length > 0)) {
          await refreshChatList();
        }
      }
    }
  } catch (err) {
    console.error('Kith EventSource: error handling state event', err);
  }

  // Handle Contact state changes (e.g., new peer discovered or contact blocked)
  if (changed.Contact) {
    if (contactState === null) {
      contactState = changed.Contact;
    } else {
      try {
        const responses = await callJmap([
          ['Contact/changes', {
            accountId: session.accountId,
            sinceState: contactState,
          }, 'cc0'],
        ]);
        const [, result] = responses[0];
        if (result.type === 'cannotCalculateChanges') {
          // fetchContacts updates contactState via Contact/get
          const contactList = await fetchContacts();
          renderContactList(contactList);
        } else if (result.type) {
          console.error('Kith: Contact/changes error:', result.type);
          contactState = changed.Contact;
        } else {
          contactState = result.newState;
          if ((result.created && result.created.length > 0) ||
              (result.updated && result.updated.length > 0) ||
              (result.destroyed && result.destroyed.length > 0)) {
            const contactList = await fetchContacts();
            renderContactList(contactList);
          }
        }
      } catch (err) {
        console.warn('Contact/changes failed:', err);
        // Non-fatal: will resync on next state event
      }
    }
  }
}

async function refreshChatList() {
  try {
    const chatList = await fetchChats();
    renderChatList(chatList);
  } catch (err) {
    console.error('Kith: failed to refresh chat list', err);
  }
}

// ---------------------------------------------------------------------------
// App entry point
// ---------------------------------------------------------------------------

async function renderApp() {
  await bootstrap();
  const contactList = await fetchContacts();
  renderContactList(contactList);
  const chatList = await fetchChats();
  renderChatList(chatList);
  setupCompose();
  startEventSource();
}

document.addEventListener('DOMContentLoaded', () => {
  renderApp().catch((err) => {
    console.error('Kith startup error:', err);
  });
});
