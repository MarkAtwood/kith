pub mod auth;
pub mod chat;
pub mod contact;
pub mod error;
pub mod events;
pub mod jmap;
pub mod message;
pub mod resultref;

// Re-export primary types at crate level for ergonomic downstream imports.
pub use auth::{Identity, Role};
pub use chat::Chat;
pub use contact::ChatContact;
pub use error::{AuthError, JmapError, KithError};
pub use events::StateChange;
pub use jmap::{Id, Invocation, JmapRequest, JmapResponse, UTCDate};
pub use message::{Attachment, DeliveryState, Message};
pub use resultref::{Argument, ResultReference};
