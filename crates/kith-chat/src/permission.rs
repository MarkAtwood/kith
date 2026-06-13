//! Permission resolution engine for Spaces (draft-atwood-jmap-chat-00 §6.1).
//!
//! Five-step resolution:
//! 1. Compute union of permissions across all SpaceRoles held by the member
//!    (including the implicit @everyone role at position 0).
//! 2. Apply `deny` entries from ChannelPermission records matching the
//!    member's roles, processed in ascending position order.
//! 3. Apply `allow` entries from the same role-targeted records, ascending
//!    position order.
//! 4. Apply `deny` entries from the ChannelPermission record targeting the
//!    member directly.
//! 5. Apply `allow` entries from the same member-targeted record.

use kith_core::KithError;
use std::collections::HashSet;

/// Resolve whether a user has a specific permission in a Space channel.
///
/// Returns `Ok(true)` if the permission is granted after the full 5-step
/// resolution, `Ok(false)` if denied or the user is not a member.
///
/// # Errors
///
/// Returns `Err` on database I/O failure.
pub fn resolve_permission(
    store: &kith_store::Store,
    space_id: &str,
    chat_id: &str,
    user_id: &str,
    permission: &str,
) -> Result<bool, KithError> {
    // Step 0: check membership.  Non-members have no permissions.
    if !store.spaces().is_member(space_id, user_id)? {
        return Ok(false);
    }

    // Step 1: compute the union of permissions from all the member's roles
    // plus the implicit @everyone role (position 0).
    let member_role_ids = store.spaces().get_member_role_ids(space_id, user_id)?;
    let all_roles = store.spaces().load_roles(space_id)?;

    let mut effective: HashSet<String> = HashSet::new();

    // Build a lookup: which role IDs the member holds.
    let member_role_set: HashSet<&str> = member_role_ids.iter().map(|s| s.as_str()).collect();

    // Union permissions from @everyone (position 0) and all member roles.
    for role in &all_roles {
        let is_everyone = role.position == 0;
        let is_member_role = member_role_set.contains(role.id.as_ref());
        if is_everyone || is_member_role {
            for perm in &role.permissions {
                effective.insert(perm.clone());
            }
        }
    }

    // Load channel permission overrides for this channel.
    let overrides = store
        .spaces()
        .load_channel_permission_overrides(chat_id)?;

    // Separate overrides into role-targeted and member-targeted.
    // For role-targeted overrides, we need to process them in ascending role
    // position order.  Build a map from role_id -> position for lookup.
    let role_position: std::collections::HashMap<&str, u64> = all_roles
        .iter()
        .map(|r| (r.id.as_ref(), r.position))
        .collect();

    // Collect role-targeted overrides that match the member's roles (including @everyone).
    let mut role_overrides: Vec<(u64, &[String], &[String])> = Vec::new();
    let mut member_override: Option<(&[String], &[String])> = None;

    for ovr in &overrides {
        if ovr.target_type == "role" {
            // Check if this role is @everyone (position 0) or one of the member's roles.
            let target_id: &str = ovr.target_id.as_ref();
            let is_everyone_role = role_position
                .get(target_id)
                .is_some_and(|&pos| pos == 0);
            if is_everyone_role || member_role_set.contains(target_id) {
                let pos = role_position.get(target_id).copied().unwrap_or(0);
                role_overrides.push((pos, &ovr.deny, &ovr.allow));
            }
        } else if ovr.target_type == "member" && ovr.target_id.as_ref() == user_id {
            member_override = Some((&ovr.deny, &ovr.allow));
        }
    }

    // Sort role-targeted overrides by position ascending.
    role_overrides.sort_by_key(|(pos, _, _)| *pos);

    // Step 2: apply deny entries from role-targeted overrides (ascending position).
    for &(_, deny, _) in &role_overrides {
        for perm in deny {
            effective.remove(perm);
        }
    }

    // Step 3: apply allow entries from role-targeted overrides (ascending position).
    for &(_, _, allow) in &role_overrides {
        for perm in allow {
            effective.insert(perm.clone());
        }
    }

    // Step 4: apply deny from member-targeted override.
    if let Some((deny, _)) = member_override {
        for perm in deny {
            effective.remove(perm);
        }
    }

    // Step 5: apply allow from member-targeted override.
    if let Some((_, allow)) = member_override {
        for perm in allow {
            effective.insert(perm.clone());
        }
    }

    Ok(effective.contains(permission))
}

/// Check whether a message has broadcast mentions.
///
/// For `text/plain` and `text/markdown` bodies, checks the `broadcastMentions`
/// array from the request object.  For `application/jmap-chat-rich`, checks
/// whether the body JSON contains any span with `type: "broadcast"`.
pub fn has_broadcast_mentions(
    obj: &serde_json::Map<String, serde_json::Value>,
    body_type: &str,
    body: &str,
) -> bool {
    if body_type == "application/jmap-chat-rich" {
        // Parse rich body and look for broadcast spans.
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(spans) = parsed.get("spans").and_then(|v| v.as_array()) {
                return spans.iter().any(|span| {
                    span.get("type").and_then(|v| v.as_str()) == Some("broadcast")
                });
            }
        }
        false
    } else {
        // Check broadcastMentions array from the request.
        match obj.get("broadcastMentions") {
            Some(serde_json::Value::Array(arr)) => !arr.is_empty(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_store::Store;

    /// Helper: create a store with a space, roles, a channel chat, and optionally
    /// set up members and channel permission overrides.
    struct TestFixture {
        store: Store,
    }

    impl TestFixture {
        fn new() -> Self {
            let store = Store::open_in_memory().expect("open in-memory store");
            Self { store }
        }

        /// Create a space with an @everyone role (position 0) and a custom role.
        fn setup_space_with_roles(
            &self,
            space_id: &str,
            everyone_perms: &[&str],
            role_id: &str,
            role_perms: &[&str],
        ) {
            self.store
                .spaces()
                .create_space(space_id, "Test Space", None, None, false, false, 1_000_000)
                .expect("create space");

            // @everyone role at position 0.
            // The add_role method has a debug_assert for position > 0, so
            // we insert @everyone directly via SQL.
            self.store
                .spaces()
                .add_everyone_role(space_id, "role-everyone", everyone_perms)
                .expect("add @everyone role");

            // Custom role at position 1.
            self.store
                .spaces()
                .add_role(space_id, role_id, "Custom Role", None, role_perms, 1)
                .expect("add custom role");
        }

        /// Create a channel chat linked to a space.
        fn setup_channel(&self, chat_id: &str, space_id: &str) {
            // Create a bare chat first, then link it to the space.
            self.store
                .chats()
                .create(chat_id, "group", None, 1_000_000)
                .expect("create chat");
            self.store
                .spaces()
                .create_channel(space_id, chat_id, "general")
                .expect("create channel");
        }

        /// Add a member to a space with specific roles.
        fn add_member(&self, space_id: &str, user_id: &str, role_ids: &[&str]) {
            self.store
                .spaces()
                .add_member(space_id, user_id, None, 1_000_000, role_ids)
                .expect("add member");
        }

        /// Add a channel permission override.
        fn add_channel_override(
            &self,
            chat_id: &str,
            target_id: &str,
            target_type: &str,
            allow: &[&str],
            deny: &[&str],
        ) {
            self.store
                .spaces()
                .set_channel_permission_override(chat_id, target_id, target_type, allow, deny)
                .expect("set channel override");
        }
    }

    // Oracle: A member who holds a role that grants "send" must resolve to true.
    // The oracle is the role permissions inserted directly — "send" is present.
    #[test]
    fn member_with_send_role_resolves_true() {
        let f = TestFixture::new();
        f.setup_space_with_roles("sp1", &["view"], "role-mod", &["send"]);
        f.setup_channel("ch1", "sp1");
        f.add_member("sp1", "user-a", &["role-mod"]);

        let result = resolve_permission(&f.store, "sp1", "ch1", "user-a", "send")
            .expect("resolve must not error");
        assert!(result, "member with 'send' role must have send permission");
    }

    // Oracle: A member who holds a role that does NOT include "send" must
    // resolve to false. The oracle is the role permissions — only "view" is present.
    #[test]
    fn member_without_send_role_resolves_false() {
        let f = TestFixture::new();
        f.setup_space_with_roles("sp1", &["view"], "role-readonly", &["view"]);
        f.setup_channel("ch1", "sp1");
        f.add_member("sp1", "user-b", &["role-readonly"]);

        let result = resolve_permission(&f.store, "sp1", "ch1", "user-b", "send")
            .expect("resolve must not error");
        assert!(
            !result,
            "member with only 'view' role must not have send permission"
        );
    }

    // Oracle: A non-member has no permissions at all.
    #[test]
    fn non_member_resolves_false() {
        let f = TestFixture::new();
        f.setup_space_with_roles("sp1", &["view", "send"], "role-mod", &["send"]);
        f.setup_channel("ch1", "sp1");
        // user-ghost is NOT added as a member.

        let result = resolve_permission(&f.store, "sp1", "ch1", "user-ghost", "send")
            .expect("resolve must not error");
        assert!(!result, "non-member must not have any permission");
    }

    // Oracle: The @everyone role (position 0) grants base permissions to all members,
    // even members with no explicitly assigned roles.
    #[test]
    fn everyone_role_grants_base_permissions() {
        let f = TestFixture::new();
        f.setup_space_with_roles("sp1", &["view", "send"], "role-mod", &["send"]);
        f.setup_channel("ch1", "sp1");
        // Add member with NO custom roles — only @everyone applies.
        f.add_member("sp1", "user-c", &[]);

        let result = resolve_permission(&f.store, "sp1", "ch1", "user-c", "send")
            .expect("resolve must not error");
        assert!(
            result,
            "@everyone grants 'send', so member with no roles should have it"
        );
    }

    // Oracle: A channel deny override for a role removes the permission from
    // that role's grant. The oracle is the 5-step algorithm: deny in step 2
    // removes what step 1 granted.
    #[test]
    fn channel_deny_override_removes_permission() {
        let f = TestFixture::new();
        f.setup_space_with_roles("sp1", &["view", "send"], "role-mod", &["send"]);
        f.setup_channel("ch1", "sp1");
        f.add_member("sp1", "user-d", &[]);

        // Deny "send" for @everyone role in this channel.
        f.add_channel_override("ch1", "role-everyone", "role", &[], &["send"]);

        let result = resolve_permission(&f.store, "sp1", "ch1", "user-d", "send")
            .expect("resolve must not error");
        assert!(
            !result,
            "channel deny override must remove 'send' from @everyone"
        );
    }

    // Oracle: A channel allow override for a role adds a permission that
    // was not granted at the space level. Step 3 adds what step 1 didn't have.
    #[test]
    fn channel_allow_override_adds_permission() {
        let f = TestFixture::new();
        // @everyone has only "view" (no "send"), role-mod also only has "view".
        f.setup_space_with_roles("sp1", &["view"], "role-mod", &["view"]);
        f.setup_channel("ch1", "sp1");
        f.add_member("sp1", "user-e", &[]);

        // Allow "send" for @everyone role in this channel.
        f.add_channel_override("ch1", "role-everyone", "role", &["send"], &[]);

        let result = resolve_permission(&f.store, "sp1", "ch1", "user-e", "send")
            .expect("resolve must not error");
        assert!(
            result,
            "channel allow override must add 'send' to @everyone"
        );
    }

    // Oracle: A member-targeted override takes precedence over role-targeted
    // overrides. Step 4/5 overrides steps 2/3. Here: role grants send, channel
    // role deny removes it, but member allow re-grants it.
    #[test]
    fn member_override_takes_precedence() {
        let f = TestFixture::new();
        f.setup_space_with_roles("sp1", &["view", "send"], "role-mod", &["send"]);
        f.setup_channel("ch1", "sp1");
        f.add_member("sp1", "user-f", &[]);

        // Deny "send" for @everyone at channel level.
        f.add_channel_override("ch1", "role-everyone", "role", &[], &["send"]);
        // But allow "send" specifically for user-f.
        f.add_channel_override("ch1", "user-f", "member", &["send"], &[]);

        let result = resolve_permission(&f.store, "sp1", "ch1", "user-f", "send")
            .expect("resolve must not error");
        assert!(
            result,
            "member allow override must override role deny override"
        );
    }

    // Oracle: Higher-position role overrides are processed after lower-position
    // role overrides. When role at position 1 denies "send" and role at
    // position 0 allows it, the deny at position 1 is processed first in step 2
    // (ascending), then position 0 allow in step 3 (ascending). Because step 3
    // re-adds it, the lower-position role's allow wins in the interleave.
    //
    // Per spec steps 2 and 3: step 2 removes ALL denies (ascending), then
    // step 3 adds ALL allows (ascending). So if position 0 denies and
    // position 1 allows, the result is allowed. If position 0 allows and
    // position 1 denies, step 2 removes it, step 3 re-adds it.
    // This test: role-mod (position 1) denies send, @everyone (position 0) has
    // it in base permissions. Step 2 removes "send" (role-mod deny). Step 3
    // has no allows that re-add it. Result: denied.
    #[test]
    fn higher_position_role_deny_overrides_lower() {
        let f = TestFixture::new();
        f.setup_space_with_roles("sp1", &["view", "send"], "role-mod", &["view"]);
        f.setup_channel("ch1", "sp1");
        f.add_member("sp1", "user-g", &["role-mod"]);

        // Deny "send" for role-mod (position 1) at channel level.
        f.add_channel_override("ch1", "role-mod", "role", &[], &["send"]);

        let result = resolve_permission(&f.store, "sp1", "ch1", "user-g", "send")
            .expect("resolve must not error");
        assert!(
            !result,
            "role deny at higher position must remove permission granted by @everyone"
        );
    }

    // Oracle: Member deny overrides even when role allows.
    // Role grants "mention_broadcast", channel allows it, but member denies it.
    // Steps 4/5: member deny in step 4, no member allow in step 5 for this perm.
    #[test]
    fn member_deny_overrides_role_allow() {
        let f = TestFixture::new();
        f.setup_space_with_roles(
            "sp1",
            &["view", "send", "mention_broadcast"],
            "role-mod",
            &["mention_broadcast"],
        );
        f.setup_channel("ch1", "sp1");
        f.add_member("sp1", "user-h", &["role-mod"]);

        // Member-targeted deny for mention_broadcast.
        f.add_channel_override("ch1", "user-h", "member", &[], &["mention_broadcast"]);

        let result =
            resolve_permission(&f.store, "sp1", "ch1", "user-h", "mention_broadcast")
                .expect("resolve must not error");
        assert!(
            !result,
            "member deny must remove permission even when role grants it"
        );
    }

    // --- has_broadcast_mentions tests ---

    // Oracle: non-empty broadcastMentions array → true.
    #[test]
    fn has_broadcast_mentions_array_nonempty() {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "broadcastMentions".to_string(),
            serde_json::json!([{"scope": "everyone", "offset": 0, "length": 9}]),
        );
        assert!(has_broadcast_mentions(&obj, "text/plain", "hello"));
    }

    // Oracle: empty broadcastMentions array → false.
    #[test]
    fn has_broadcast_mentions_array_empty() {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "broadcastMentions".to_string(),
            serde_json::json!([]),
        );
        assert!(!has_broadcast_mentions(&obj, "text/plain", "hello"));
    }

    // Oracle: rich body with broadcast span → true.
    #[test]
    fn has_broadcast_mentions_rich_body() {
        let obj = serde_json::Map::new();
        let body = r#"{"spans":[{"type":"broadcast","scope":"everyone","text":"@everyone"}]}"#;
        assert!(has_broadcast_mentions(&obj, "application/jmap-chat-rich", body));
    }

    // Oracle: rich body without broadcast span → false.
    #[test]
    fn has_broadcast_mentions_rich_body_no_broadcast() {
        let obj = serde_json::Map::new();
        let body = r#"{"spans":[{"type":"text","text":"hello"}]}"#;
        assert!(!has_broadcast_mentions(
            &obj,
            "application/jmap-chat-rich",
            body
        ));
    }
}
