//! Space-layer store operations (draft-atwood-jmap-chat-00 §4.20-4.27).
//!
//! Provides CRUD for Space, SpaceRole, SpaceMember, Category,
//! SpaceInvite, SpaceBan, and channel permission overrides.

use crate::db_err;
use kith_core::{
    make_category, make_channel_permission, make_space_member, make_space_role, Category,
    ChannelPermission, Id, KithError, Space, SpaceBan, SpaceInvite, SpaceMember, SpaceRole,
    StateChange, UTCDate,
};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::broadcast;

// ── Space row helpers ────────────────────────────────────────────────────

/// Intermediate struct for raw DB row values from the `spaces` table.
struct SpaceRow {
    id: String,
    name: String,
    description: Option<String>,
    icon_blob_id: Option<String>,
    is_public: bool,
    is_publicly_previewable: bool,
    created_at: i64,
}

/// Extract a [`SpaceRow`] from a rusqlite `Row`.
fn extract_space_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SpaceRow> {
    let is_public_i: i64 = row.get(4)?;
    let is_previewable_i: i64 = row.get(5)?;
    Ok(SpaceRow {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        icon_blob_id: row.get(3)?,
        is_public: is_public_i != 0,
        is_publicly_previewable: is_previewable_i != 0,
        created_at: row.get(6)?,
    })
}

/// Build a [`Space`] from a [`SpaceRow`] and pre-loaded sub-arrays.
fn build_space(r: SpaceRow, roles: Vec<SpaceRole>, members: Vec<SpaceMember>) -> Space {
    let member_count = members.len() as u64;
    let created_at_str = crate::util::unix_secs_to_rfc3339(r.created_at.max(0) as u64);
    let mut space = Space::new(
        Id::from(r.id),
        r.name,
        roles,
        members,
        vec![],
        vec![],
        UTCDate::from(created_at_str),
        r.is_public,
        r.is_publicly_previewable,
        member_count,
    );
    space.description = r.description;
    space.icon_blob_id = r.icon_blob_id.map(Id::from);
    space
}

// ── Invite row helpers ───────────────────────────────────────────────────

struct InviteRow {
    id: String,
    code: String,
    space_id: String,
    created_by: String,
    default_channel_id: Option<String>,
    expires_at: Option<i64>,
    max_uses: Option<i64>,
    uses: i64,
    created_at: i64,
}

fn build_space_invite(r: InviteRow) -> SpaceInvite {
    let created_at_str = crate::util::unix_secs_to_rfc3339(r.created_at.max(0) as u64);
    let expires_at_utc = r
        .expires_at
        .map(|ts| UTCDate::from(crate::util::unix_secs_to_rfc3339(ts.max(0) as u64)));
    let max_uses_u64 = r.max_uses.map(|v| v.max(0) as u64);
    SpaceInvite::new(
        Id::from(r.id),
        r.code,
        Id::from(r.space_id),
        Id::from(r.created_by),
        r.uses.max(0) as u64,
        UTCDate::from(created_at_str),
        r.default_channel_id.map(Id::from),
        expires_at_utc,
        max_uses_u64,
    )
}

// ── Ban row helpers ──────────────────────────────────────────────────────

struct BanRow {
    id: String,
    space_id: String,
    user_id: String,
    banned_by: String,
    reason: Option<String>,
    created_at: i64,
    expires_at: Option<i64>,
}

fn build_space_ban(r: BanRow) -> SpaceBan {
    let created_at_str = crate::util::unix_secs_to_rfc3339(r.created_at.max(0) as u64);
    let mut ban = SpaceBan::new(
        Id::from(r.id),
        Id::from(r.space_id),
        Id::from(r.user_id),
        Id::from(r.banned_by),
        UTCDate::from(created_at_str),
    );
    ban.reason = r.reason;
    ban.expires_at = r
        .expires_at
        .map(|ts| UTCDate::from(crate::util::unix_secs_to_rfc3339(ts.max(0) as u64)));
    ban
}

// ── RFC 3339 parser (for invite validity checks) ─────────────────────────

/// Parse a simple RFC 3339 UTC timestamp (ending in 'Z') to Unix seconds.
///
/// Only supports the format produced by `unix_secs_to_rfc3339`: `YYYY-MM-DDTHH:MM:SSZ`.
/// Returns `None` for any other format.
fn parse_rfc3339_to_unix(s: &str) -> Option<i64> {
    if s.len() != 20 || !s.ends_with('Z') {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day: i64 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let min: i64 = s[14..16].parse().ok()?;
    let sec: i64 = s[17..19].parse().ok()?;

    // Hinnant civil-to-days algorithm (inverse of unix_secs_to_rfc3339).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

// ── SpaceStore ───────────────────────────────────────────────────────────

/// Store view for Space-layer operations.
pub struct SpaceStore<'a> {
    conn: &'a Connection,
    events_tx: Option<&'a broadcast::Sender<StateChange>>,
}

impl<'a> SpaceStore<'a> {
    pub(crate) fn new(
        conn: &'a Connection,
        events_tx: Option<&'a broadcast::Sender<StateChange>>,
    ) -> Self {
        Self { conn, events_tx }
    }

    fn emit(&self, type_name: &str, new_state: String) {
        if let Some(tx) = self.events_tx {
            let _ = tx.send(StateChange {
                type_name: type_name.to_string(),
                new_state,
            });
        }
    }

    // ── Space CRUD ──────────────────────────────────────────────────────

    /// Create a new Space. Advances the space state counter.
    #[allow(clippy::too_many_arguments)]
    pub fn create_space(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        icon_blob_id: Option<&str>,
        is_public: bool,
        is_publicly_previewable: bool,
        created_at_unix: i64,
    ) -> Result<Space, KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "INSERT INTO spaces \
             (id, name, description, icon_blob_id, is_public, is_publicly_previewable, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                name,
                description,
                icon_blob_id,
                is_public as i64,
                is_publicly_previewable as i64,
                created_at_unix,
            ],
        )
        .map_err(db_err)?;

        let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
        tx.execute(
            "UPDATE spaces SET changed_at_counter = ?1, created_at_counter = ?1 WHERE id = ?2",
            params![counter, id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit("Space", format!("s-{counter}"));

        let row = SpaceRow {
            id: id.to_string(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            icon_blob_id: icon_blob_id.map(|s| s.to_string()),
            is_public,
            is_publicly_previewable,
            created_at: created_at_unix,
        };
        Ok(build_space(row, vec![], vec![]))
    }

    /// Fetch a single Space by ID, loading its roles, members, and categories.
    ///
    /// Returns `Ok(None)` if the space does not exist.
    pub fn get_space(&self, id: &str) -> Result<Option<Space>, KithError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, description, icon_blob_id, is_public, \
                 is_publicly_previewable, created_at \
                 FROM spaces WHERE id = ?1",
                params![id],
                extract_space_row,
            )
            .optional()
            .map_err(db_err)?;

        let r = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let roles = self.load_roles(&r.id)?;
        let members = self.load_members(&r.id)?;
        Ok(Some(build_space(r, roles, members)))
    }

    /// List all spaces with sub-arrays (roles, members) loaded.
    pub fn list_spaces(&self) -> Result<Vec<Space>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, name, description, icon_blob_id, is_public, \
                 is_publicly_previewable, created_at \
                 FROM spaces ORDER BY created_at ASC",
            )
            .map_err(db_err)?;

        let rows: Vec<SpaceRow> = stmt
            .query_map([], extract_space_row)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut spaces = Vec::with_capacity(rows.len());
        for r in rows {
            let roles = self.load_roles(&r.id)?;
            let members = self.load_members(&r.id)?;
            spaces.push(build_space(r, roles, members));
        }
        Ok(spaces)
    }

    /// Update mutable Space metadata fields. Advances the state counter.
    pub fn update_space_metadata(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<Option<&str>>,
        icon_blob_id: Option<Option<&str>>,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // Build dynamic SET clauses based on which fields were supplied.
        let mut sets = Vec::new();
        let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut param_idx = 1u32;

        if let Some(n) = name {
            sets.push(format!("name = ?{param_idx}"));
            values.push(Box::new(n.to_string()));
            param_idx += 1;
        }
        if let Some(d) = description {
            sets.push(format!("description = ?{param_idx}"));
            values.push(Box::new(d.map(|s| s.to_string())));
            param_idx += 1;
        }
        if let Some(b) = icon_blob_id {
            sets.push(format!("icon_blob_id = ?{param_idx}"));
            values.push(Box::new(b.map(|s| s.to_string())));
            param_idx += 1;
        }

        if sets.is_empty() {
            return Ok(());
        }

        let sql = format!(
            "UPDATE spaces SET {} WHERE id = ?{param_idx}",
            sets.join(", ")
        );
        values.push(Box::new(id.to_string()));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> = values.iter().map(|v| &**v).collect();
        let affected = tx.execute(&sql, params_refs.as_slice()).map_err(db_err)?;

        if affected > 0 {
            let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
            tx.execute(
                "UPDATE spaces SET changed_at_counter = ?1 WHERE id = ?2",
                params![counter, id],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            self.emit("Space", format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
        }
        Ok(())
    }

    /// Delete a Space and all its dependent rows (CASCADE). Advances the state counter.
    pub fn delete_space(&self, id: &str) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute("DELETE FROM spaces WHERE id = ?1", params![id])
            .map_err(db_err)?;

        if affected > 0 {
            let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
            tx.commit().map_err(db_err)?;
            self.emit("Space", format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
        }
        Ok(())
    }

    /// Return the current space state counter as a string token.
    pub fn get_state(&self) -> Result<String, KithError> {
        let counter: i64 = self
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'space'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(format!("s-{counter}"))
    }

    /// Return IDs of spaces that were changed or destroyed since `since_state`.
    ///
    /// Returns `(changed_ids, destroyed_ids, new_state)`.
    ///
    /// Spaces that still exist in the DB with `changed_at_counter > since` appear
    /// in `changed_ids`. Spaces deleted since `since_state` cannot be tracked
    /// without a tombstone table, so `destroyed_ids` is always empty in Phase 1.
    pub fn get_changes_since(
        &self,
        since_state: &str,
    ) -> Result<(Vec<String>, Vec<String>, String), KithError> {
        let since_counter = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Jmap(kith_core::JmapError::cannot_calculate_changes()))?;

        let current_state = self.get_state()?;
        let current_counter: i64 = current_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .expect("get_state always returns s-<integer>");

        if since_counter >= current_counter {
            return Ok((vec![], vec![], current_state));
        }

        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id FROM spaces \
                 WHERE changed_at_counter > ?1 ORDER BY changed_at_counter ASC",
            )
            .map_err(db_err)?;

        let changed: Vec<String> = stmt
            .query_map(params![since_counter], |row| row.get(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        // Phase 1: no tombstone table, so destroyed is always empty.
        Ok((changed, vec![], current_state))
    }

    /// Return change rows ordered by `changed_at_counter` with create/update
    /// distinction, suitable for RFC 8620 §5.2 created[] vs updated[].
    ///
    /// Each row is `(space_id, changed_at_counter, is_create)`.
    /// `is_create` is true when `created_at_counter > since_counter`.
    pub fn get_changes_since_ordered(
        &self,
        since_state: &str,
    ) -> Result<(Vec<(String, i64, bool)>, String), KithError> {
        let since_counter = since_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| KithError::Jmap(kith_core::JmapError::cannot_calculate_changes()))?;

        let current_state = self.get_state()?;
        let current_counter: i64 = current_state
            .strip_prefix("s-")
            .and_then(|n| n.parse::<i64>().ok())
            .expect("get_state always returns s-<integer>");

        if since_counter >= current_counter {
            return Ok((vec![], current_state));
        }

        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, changed_at_counter, created_at_counter \
                 FROM spaces WHERE changed_at_counter > ?1 ORDER BY changed_at_counter ASC",
            )
            .map_err(db_err)?;

        let rows: Vec<(String, i64, bool)> = stmt
            .query_map(params![since_counter], |row| {
                let id: String = row.get(0)?;
                let changed_at: i64 = row.get(1)?;
                let created_at: i64 = row.get(2)?;
                let is_create = created_at > since_counter;
                Ok((id, changed_at, is_create))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok((rows, current_state))
    }

    // ── SpaceRole CRUD ──────────────────────────────────────────────────

    /// Add a role to a space. Inserts the role row and its permissions.
    /// Advances the space state counter.
    #[allow(clippy::too_many_arguments)]
    pub fn add_role(
        &self,
        space_id: &str,
        role_id: &str,
        name: &str,
        color: Option<&str>,
        permissions: &[&str],
        position: u64,
    ) -> Result<(), KithError> {
        debug_assert!(
            position > 0,
            "position 0 is reserved for @everyone; got position={position}"
        );

        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // Verify the space exists.
        let space_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM spaces WHERE id = ?1)",
                params![space_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        debug_assert!(
            space_exists,
            "add_role: space_id '{space_id}' does not exist"
        );

        let pos_i64 =
            i64::try_from(position).map_err(|_| KithError::Store("position overflow".into()))?;
        tx.execute(
            "INSERT INTO space_roles (id, space_id, name, color, position) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![role_id, space_id, name, color, pos_i64],
        )
        .map_err(db_err)?;

        for perm in permissions {
            tx.execute(
                "INSERT INTO space_role_permissions (role_id, permission) VALUES (?1, ?2)",
                params![role_id, perm],
            )
            .map_err(db_err)?;
        }

        let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
        tx.execute(
            "UPDATE spaces SET changed_at_counter = ?1 WHERE id = ?2",
            params![counter, space_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit("Space", format!("s-{counter}"));
        Ok(())
    }

    /// Remove a role by ID. Cascades to permissions and member_roles.
    /// Advances the space state counter.
    pub fn remove_role(&self, role_id: &str) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // Look up the space_id before deleting so we can stamp it.
        let space_id: Option<String> = tx
            .query_row(
                "SELECT space_id FROM space_roles WHERE id = ?1",
                params![role_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err)?;

        let affected = tx
            .execute("DELETE FROM space_roles WHERE id = ?1", params![role_id])
            .map_err(db_err)?;

        if affected > 0 {
            let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
            if let Some(ref sid) = space_id {
                tx.execute(
                    "UPDATE spaces SET changed_at_counter = ?1 WHERE id = ?2",
                    params![counter, sid],
                )
                .map_err(db_err)?;
            }
            tx.commit().map_err(db_err)?;
            self.emit("Space", format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
        }
        Ok(())
    }

    /// Update a role's name, color, permissions, and position.
    /// Replaces the permission set entirely (DELETE + re-INSERT).
    pub fn update_role(
        &self,
        role_id: &str,
        name: Option<&str>,
        color: Option<Option<&str>>,
        permissions: Option<&[&str]>,
        position: Option<u64>,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // Look up the space_id.
        let space_id: String = tx
            .query_row(
                "SELECT space_id FROM space_roles WHERE id = ?1",
                params![role_id],
                |row| row.get(0),
            )
            .map_err(|e| {
                if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                    KithError::Store(format!("update_role: role '{role_id}' not found"))
                } else {
                    db_err(e)
                }
            })?;

        if let Some(n) = name {
            tx.execute(
                "UPDATE space_roles SET name = ?1 WHERE id = ?2",
                params![n, role_id],
            )
            .map_err(db_err)?;
        }
        if let Some(c) = color {
            tx.execute(
                "UPDATE space_roles SET color = ?1 WHERE id = ?2",
                params![c, role_id],
            )
            .map_err(db_err)?;
        }
        if let Some(pos) = position {
            let pos_i64 =
                i64::try_from(pos).map_err(|_| KithError::Store("position overflow".into()))?;
            tx.execute(
                "UPDATE space_roles SET position = ?1 WHERE id = ?2",
                params![pos_i64, role_id],
            )
            .map_err(db_err)?;
        }
        if let Some(perms) = permissions {
            tx.execute(
                "DELETE FROM space_role_permissions WHERE role_id = ?1",
                params![role_id],
            )
            .map_err(db_err)?;
            for perm in perms {
                tx.execute(
                    "INSERT INTO space_role_permissions (role_id, permission) VALUES (?1, ?2)",
                    params![role_id, perm],
                )
                .map_err(db_err)?;
            }
        }

        let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
        tx.execute(
            "UPDATE spaces SET changed_at_counter = ?1 WHERE id = ?2",
            params![counter, space_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit("Space", format!("s-{counter}"));
        Ok(())
    }

    /// Load all roles (with permissions) for a space.
    pub fn load_roles(&self, space_id: &str) -> Result<Vec<SpaceRole>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, name, color, position FROM space_roles \
                 WHERE space_id = ?1 ORDER BY position ASC",
            )
            .map_err(db_err)?;

        let raw_roles: Vec<(String, String, Option<String>, i64)> = stmt
            .query_map(params![space_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut roles = Vec::with_capacity(raw_roles.len());
        for (rid, rname, rcolor, rpos) in raw_roles {
            let perms = self.load_role_permissions(&rid)?;
            let mut role = make_space_role(&rid, rname, perms, rpos.max(0) as u64);
            role.color = rcolor;
            roles.push(role);
        }
        Ok(roles)
    }

    /// Load permissions for a single role.
    fn load_role_permissions(&self, role_id: &str) -> Result<Vec<String>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT permission FROM space_role_permissions \
                 WHERE role_id = ?1 ORDER BY permission",
            )
            .map_err(db_err)?;

        let perms: Vec<String> = stmt
            .query_map(params![role_id], |row| row.get(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok(perms)
    }

    // ── SpaceMember CRUD ────────────────────────────────────────────────

    /// Add a member to a space with optional nick and role assignments.
    /// Advances the space state counter.
    pub fn add_member(
        &self,
        space_id: &str,
        user_id: &str,
        nick: Option<&str>,
        joined_at_unix: i64,
        role_ids: &[&str],
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // Verify the space exists.
        let space_exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM spaces WHERE id = ?1)",
                params![space_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        debug_assert!(
            space_exists,
            "add_member: space_id '{space_id}' does not exist"
        );

        tx.execute(
            "INSERT INTO space_members (space_id, user_id, nick, joined_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![space_id, user_id, nick, joined_at_unix],
        )
        .map_err(db_err)?;

        for rid in role_ids {
            tx.execute(
                "INSERT INTO space_member_roles (space_id, user_id, role_id) \
                 VALUES (?1, ?2, ?3)",
                params![space_id, user_id, rid],
            )
            .map_err(db_err)?;
        }

        let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
        tx.execute(
            "UPDATE spaces SET changed_at_counter = ?1 WHERE id = ?2",
            params![counter, space_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit("Space", format!("s-{counter}"));
        Ok(())
    }

    /// Remove a member from a space. Cascades to member_roles.
    /// Advances the space state counter.
    pub fn remove_member(&self, space_id: &str, user_id: &str) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let affected = tx
            .execute(
                "DELETE FROM space_members WHERE space_id = ?1 AND user_id = ?2",
                params![space_id, user_id],
            )
            .map_err(db_err)?;

        if affected > 0 {
            let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
            tx.execute(
                "UPDATE spaces SET changed_at_counter = ?1 WHERE id = ?2",
                params![counter, space_id],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            self.emit("Space", format!("s-{counter}"));
        } else {
            tx.commit().map_err(db_err)?;
        }
        Ok(())
    }

    /// Update a member's nick and replace their role assignments.
    pub fn update_member(
        &self,
        space_id: &str,
        user_id: &str,
        nick: Option<Option<&str>>,
        role_ids: Option<&[&str]>,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        if let Some(n) = nick {
            tx.execute(
                "UPDATE space_members SET nick = ?1 WHERE space_id = ?2 AND user_id = ?3",
                params![n, space_id, user_id],
            )
            .map_err(db_err)?;
        }

        if let Some(rids) = role_ids {
            tx.execute(
                "DELETE FROM space_member_roles WHERE space_id = ?1 AND user_id = ?2",
                params![space_id, user_id],
            )
            .map_err(db_err)?;
            for rid in rids {
                tx.execute(
                    "INSERT INTO space_member_roles (space_id, user_id, role_id) \
                     VALUES (?1, ?2, ?3)",
                    params![space_id, user_id, rid],
                )
                .map_err(db_err)?;
            }
        }

        let counter = crate::advance_state_counter_in_tx(&tx, "space")?;
        tx.execute(
            "UPDATE spaces SET changed_at_counter = ?1 WHERE id = ?2",
            params![counter, space_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        self.emit("Space", format!("s-{counter}"));
        Ok(())
    }

    /// Load all members (with role_ids) for a space.
    pub fn load_members(&self, space_id: &str) -> Result<Vec<SpaceMember>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT user_id, nick, joined_at FROM space_members \
                 WHERE space_id = ?1 ORDER BY joined_at ASC",
            )
            .map_err(db_err)?;

        let raw_members: Vec<(String, Option<String>, i64)> = stmt
            .query_map(params![space_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut members = Vec::with_capacity(raw_members.len());
        for (uid, nick, joined_at) in raw_members {
            let role_ids = self.get_member_role_ids(space_id, &uid)?;
            let joined_at_str = crate::util::unix_secs_to_rfc3339(joined_at.max(0) as u64);
            let mut member = make_space_member(&uid, role_ids, joined_at_str);
            member.nick = nick;
            members.push(member);
        }
        Ok(members)
    }

    /// Check whether a user is a member of a space.
    pub fn is_member(&self, space_id: &str, user_id: &str) -> Result<bool, KithError> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM space_members WHERE space_id = ?1 AND user_id = ?2)",
                params![space_id, user_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(exists)
    }

    /// Return the role IDs assigned to a member.
    pub fn get_member_role_ids(
        &self,
        space_id: &str,
        user_id: &str,
    ) -> Result<Vec<String>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT role_id FROM space_member_roles \
                 WHERE space_id = ?1 AND user_id = ?2 ORDER BY role_id",
            )
            .map_err(db_err)?;

        let ids: Vec<String> = stmt
            .query_map(params![space_id, user_id], |row| row.get(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok(ids)
    }

    // ── Category CRUD ───────────────────────────────────────────────────

    /// Insert a new category.
    pub fn add_category(
        &self,
        space_id: &str,
        category_id: &str,
        name: &str,
        position: i64,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "INSERT INTO categories (id, space_id, name, position) VALUES (?1, ?2, ?3, ?4)",
                params![category_id, space_id, name, position],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Delete a category.  ON DELETE CASCADE removes category_channels rows.
    pub fn remove_category(&self, category_id: &str) -> Result<(), KithError> {
        self.conn
            .execute("DELETE FROM categories WHERE id = ?1", params![category_id])
            .map_err(db_err)?;
        Ok(())
    }

    /// Update a category's name and position.
    pub fn update_category(
        &self,
        category_id: &str,
        name: &str,
        position: i64,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "UPDATE categories SET name = ?1, position = ?2 WHERE id = ?3",
                params![name, position, category_id],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Load all categories for a space, each populated with its channel IDs.
    pub fn load_categories(&self, space_id: &str) -> Result<Vec<Category>, KithError> {
        let mut cat_stmt = self
            .conn
            .prepare_cached(
                "SELECT id, name, position FROM categories WHERE space_id = ?1 ORDER BY position",
            )
            .map_err(db_err)?;
        let cats: Vec<(String, String, i64)> = cat_stmt
            .query_map(params![space_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut ch_stmt = self
            .conn
            .prepare_cached(
                "SELECT chat_id FROM category_channels \
                 WHERE category_id = ?1 ORDER BY position",
            )
            .map_err(db_err)?;

        let mut result = Vec::with_capacity(cats.len());
        for (id, name, position) in cats {
            let channel_ids: Vec<String> = ch_stmt
                .query_map(params![id], |row| row.get::<_, String>(0))
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            let pos = if position >= 0 { position as u64 } else { 0 };
            result.push(make_category(&id, &name, pos, channel_ids));
        }

        Ok(result)
    }

    /// Assign a channel (chat) to a category at a given position.
    pub fn assign_channel_to_category(
        &self,
        category_id: &str,
        chat_id: &str,
        position: i64,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO category_channels (category_id, chat_id, position) \
                 VALUES (?1, ?2, ?3)",
                params![category_id, chat_id, position],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Remove a channel from a category.
    pub fn remove_channel_from_category(
        &self,
        category_id: &str,
        chat_id: &str,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "DELETE FROM category_channels WHERE category_id = ?1 AND chat_id = ?2",
                params![category_id, chat_id],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Return channel IDs that have a space_id set but are not assigned to any category.
    pub fn get_uncategorized_channel_ids(
        &self,
        space_id: &str,
    ) -> Result<Vec<String>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id FROM chats \
                 WHERE space_id = ?1 \
                   AND id NOT IN (SELECT chat_id FROM category_channels) \
                 ORDER BY id",
            )
            .map_err(db_err)?;
        let ids = stmt
            .query_map(params![space_id], |row| row.get::<_, String>(0))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(ids)
    }

    // ── Channel management ──────────────────────────────────────────────

    /// Associate a chat with a space as a channel.
    ///
    /// Updates the existing chat row to set space_id, kind='channel', and name.
    pub fn create_channel(
        &self,
        space_id: &str,
        chat_id: &str,
        name: &str,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "UPDATE chats SET space_id = ?1, kind = 'channel', name = ?2 WHERE id = ?3",
                params![space_id, name, chat_id],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Replace all permission overrides for a channel in a single transaction.
    pub fn set_channel_permission_overrides(
        &self,
        chat_id: &str,
        overrides: &[ChannelPermission],
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // Delete existing overrides for this channel.
        tx.execute(
            "DELETE FROM channel_permissions WHERE chat_id = ?1",
            params![chat_id],
        )
        .map_err(db_err)?;

        for perm in overrides {
            let target_id: &str = perm.target_id.as_ref();
            tx.execute(
                "INSERT INTO channel_permissions (chat_id, target_id, target_type) \
                 VALUES (?1, ?2, ?3)",
                params![chat_id, target_id, &perm.target_type],
            )
            .map_err(db_err)?;

            for allow_perm in &perm.allow {
                tx.execute(
                    "INSERT INTO channel_permission_entries \
                     (chat_id, target_id, permission, effect) VALUES (?1, ?2, ?3, 'allow')",
                    params![chat_id, target_id, allow_perm],
                )
                .map_err(db_err)?;
            }

            for deny_perm in &perm.deny {
                tx.execute(
                    "INSERT INTO channel_permission_entries \
                     (chat_id, target_id, permission, effect) VALUES (?1, ?2, ?3, 'deny')",
                    params![chat_id, target_id, deny_perm],
                )
                .map_err(db_err)?;
            }
        }

        tx.commit().map_err(db_err)?;
        Ok(())
    }

    /// Load all permission overrides for a channel.
    pub fn load_channel_permission_overrides(
        &self,
        chat_id: &str,
    ) -> Result<Vec<ChannelPermission>, KithError> {
        let mut target_stmt = self
            .conn
            .prepare_cached(
                "SELECT target_id, target_type FROM channel_permissions \
                 WHERE chat_id = ?1 ORDER BY target_id",
            )
            .map_err(db_err)?;
        let targets: Vec<(String, String)> = target_stmt
            .query_map(params![chat_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut entry_stmt = self
            .conn
            .prepare_cached(
                "SELECT permission, effect FROM channel_permission_entries \
                 WHERE chat_id = ?1 AND target_id = ?2 ORDER BY permission",
            )
            .map_err(db_err)?;

        let mut result = Vec::with_capacity(targets.len());
        for (target_id, target_type) in targets {
            let entries: Vec<(String, String)> = entry_stmt
                .query_map(params![chat_id, &target_id], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;

            let mut allow = Vec::new();
            let mut deny = Vec::new();
            for (perm, effect) in entries {
                match effect.as_str() {
                    "allow" => allow.push(perm),
                    "deny" => deny.push(perm),
                    _ => {}
                }
            }

            result.push(make_channel_permission(&target_id, &target_type, allow, deny));
        }

        Ok(result)
    }

    // ── SpaceInvite CRUD ────────────────────────────────────────────────

    /// Return the current space_invite state counter as a string token.
    pub fn get_invite_state(&self) -> Result<String, KithError> {
        let counter: i64 = self
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'space_invite'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(format!("s-{counter}"))
    }

    /// List all invites across all spaces.
    pub fn list_all_invites(&self) -> Result<Vec<SpaceInvite>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, code, space_id, created_by, default_channel_id, \
                        expires_at, max_uses, uses, created_at \
                 FROM space_invites ORDER BY created_at",
            )
            .map_err(db_err)?;
        let rows: Vec<InviteRow> = stmt
            .query_map([], |row| {
                Ok(InviteRow {
                    id: row.get(0)?,
                    code: row.get(1)?,
                    space_id: row.get(2)?,
                    created_by: row.get(3)?,
                    default_channel_id: row.get(4)?,
                    expires_at: row.get(5)?,
                    max_uses: row.get(6)?,
                    uses: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows.into_iter().map(build_space_invite).collect())
    }

    /// Create a new space invite.
    #[allow(clippy::too_many_arguments)]
    pub fn create_invite(
        &self,
        id: &str,
        code: &str,
        space_id: &str,
        created_by: &str,
        default_channel_id: Option<&str>,
        expires_at: Option<i64>,
        max_uses: Option<i64>,
        created_at_unix: i64,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "INSERT INTO space_invites \
             (id, code, space_id, created_by, default_channel_id, expires_at, max_uses, uses, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)",
            params![id, code, space_id, created_by, default_channel_id, expires_at, max_uses, created_at_unix],
        )
        .map_err(db_err)?;
        let counter = crate::advance_state_counter_in_tx(&tx, "space_invite")?;
        tx.commit().map_err(db_err)?;
        self.emit("SpaceInvite", format!("s-{counter}"));
        Ok(())
    }

    /// Get a space invite by ID.
    pub fn get_invite(&self, id: &str) -> Result<Option<SpaceInvite>, KithError> {
        let row = self.conn.query_row(
            "SELECT id, code, space_id, created_by, default_channel_id, \
                    expires_at, max_uses, uses, created_at \
             FROM space_invites WHERE id = ?1",
            params![id],
            |row| {
                Ok(InviteRow {
                    id: row.get(0)?,
                    code: row.get(1)?,
                    space_id: row.get(2)?,
                    created_by: row.get(3)?,
                    default_channel_id: row.get(4)?,
                    expires_at: row.get(5)?,
                    max_uses: row.get(6)?,
                    uses: row.get(7)?,
                    created_at: row.get(8)?,
                })
            },
        );
        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
            Ok(r) => Ok(Some(build_space_invite(r))),
        }
    }

    /// Find a space invite by its unique code.
    pub fn resolve_invite_by_code(&self, code: &str) -> Result<Option<SpaceInvite>, KithError> {
        let row = self.conn.query_row(
            "SELECT id, code, space_id, created_by, default_channel_id, \
                    expires_at, max_uses, uses, created_at \
             FROM space_invites WHERE code = ?1",
            params![code],
            |row| {
                Ok(InviteRow {
                    id: row.get(0)?,
                    code: row.get(1)?,
                    space_id: row.get(2)?,
                    created_by: row.get(3)?,
                    default_channel_id: row.get(4)?,
                    expires_at: row.get(5)?,
                    max_uses: row.get(6)?,
                    uses: row.get(7)?,
                    created_at: row.get(8)?,
                })
            },
        );
        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
            Ok(r) => Ok(Some(build_space_invite(r))),
        }
    }

    /// Increment the use count of a space invite.
    pub fn increment_invite_uses(&self, id: &str) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "UPDATE space_invites SET uses = uses + 1 WHERE id = ?1",
            params![id],
        )
        .map_err(db_err)?;
        let counter = crate::advance_state_counter_in_tx(&tx, "space_invite")?;
        tx.commit().map_err(db_err)?;
        self.emit("SpaceInvite", format!("s-{counter}"));
        Ok(())
    }

    /// Delete a space invite.
    pub fn delete_invite(&self, id: &str) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute("DELETE FROM space_invites WHERE id = ?1", params![id])
            .map_err(db_err)?;
        let counter = crate::advance_state_counter_in_tx(&tx, "space_invite")?;
        tx.commit().map_err(db_err)?;
        self.emit("SpaceInvite", format!("s-{counter}"));
        Ok(())
    }

    /// List all invites for a space.
    pub fn list_invites_for_space(
        &self,
        space_id: &str,
    ) -> Result<Vec<SpaceInvite>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, code, space_id, created_by, default_channel_id, \
                        expires_at, max_uses, uses, created_at \
                 FROM space_invites WHERE space_id = ?1 ORDER BY created_at",
            )
            .map_err(db_err)?;
        let rows: Vec<InviteRow> = stmt
            .query_map(params![space_id], |row| {
                Ok(InviteRow {
                    id: row.get(0)?,
                    code: row.get(1)?,
                    space_id: row.get(2)?,
                    created_by: row.get(3)?,
                    default_channel_id: row.get(4)?,
                    expires_at: row.get(5)?,
                    max_uses: row.get(6)?,
                    uses: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows.into_iter().map(build_space_invite).collect())
    }

    /// Check whether an invite is still valid (not expired, not exhausted).
    ///
    /// Pure function -- does not touch the database.
    pub fn is_invite_valid(invite: &SpaceInvite, now_unix: i64) -> bool {
        if let Some(ref expires_at) = invite.expires_at {
            let expires_str: &str = expires_at.as_ref();
            if let Some(expires_secs) = parse_rfc3339_to_unix(expires_str) {
                if now_unix >= expires_secs {
                    return false;
                }
            }
        }
        if let Some(max) = invite.max_uses {
            if invite.uses >= max {
                return false;
            }
        }
        true
    }

    // ── SpaceBan CRUD ───────────────────────────────────────────────────

    /// Return the current space_ban state counter as a string token.
    pub fn get_ban_state(&self) -> Result<String, KithError> {
        let counter: i64 = self
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'space_ban'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(format!("s-{counter}"))
    }

    /// List all bans across all spaces.
    pub fn list_all_bans(&self) -> Result<Vec<SpaceBan>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, space_id, user_id, banned_by, reason, created_at, expires_at \
                 FROM space_bans ORDER BY created_at",
            )
            .map_err(db_err)?;
        let rows: Vec<BanRow> = stmt
            .query_map([], |row| {
                Ok(BanRow {
                    id: row.get(0)?,
                    space_id: row.get(1)?,
                    user_id: row.get(2)?,
                    banned_by: row.get(3)?,
                    reason: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                })
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows.into_iter().map(build_space_ban).collect())
    }

    /// Create a new space ban.
    #[allow(clippy::too_many_arguments)]
    pub fn create_ban(
        &self,
        id: &str,
        space_id: &str,
        user_id: &str,
        banned_by: &str,
        reason: Option<&str>,
        created_at_unix: i64,
        expires_at: Option<i64>,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "INSERT INTO space_bans \
             (id, space_id, user_id, banned_by, reason, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, space_id, user_id, banned_by, reason, created_at_unix, expires_at],
        )
        .map_err(db_err)?;
        let counter = crate::advance_state_counter_in_tx(&tx, "space_ban")?;
        tx.commit().map_err(db_err)?;
        self.emit("SpaceBan", format!("s-{counter}"));
        Ok(())
    }

    /// Get a ban by ID.
    pub fn get_ban(&self, id: &str) -> Result<Option<SpaceBan>, KithError> {
        let row = self.conn.query_row(
            "SELECT id, space_id, user_id, banned_by, reason, created_at, expires_at \
             FROM space_bans WHERE id = ?1",
            params![id],
            |row| {
                Ok(BanRow {
                    id: row.get(0)?,
                    space_id: row.get(1)?,
                    user_id: row.get(2)?,
                    banned_by: row.get(3)?,
                    reason: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                })
            },
        );
        match row {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
            Ok(r) => Ok(Some(build_space_ban(r))),
        }
    }

    /// Check if a user is currently banned from a space (not expired).
    pub fn is_banned(
        &self,
        space_id: &str,
        user_id: &str,
        now_unix: i64,
    ) -> Result<bool, KithError> {
        let banned: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(\
                     SELECT 1 FROM space_bans \
                     WHERE space_id = ?1 AND user_id = ?2 \
                       AND (expires_at IS NULL OR expires_at > ?3)\
                 )",
                params![space_id, user_id, now_unix],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(banned)
    }

    /// Delete (lift) a ban.
    pub fn delete_ban(&self, id: &str) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute("DELETE FROM space_bans WHERE id = ?1", params![id])
            .map_err(db_err)?;
        let counter = crate::advance_state_counter_in_tx(&tx, "space_ban")?;
        tx.commit().map_err(db_err)?;
        self.emit("SpaceBan", format!("s-{counter}"));
        Ok(())
    }

    /// List all bans for a space.
    pub fn list_bans_for_space(&self, space_id: &str) -> Result<Vec<SpaceBan>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, space_id, user_id, banned_by, reason, created_at, expires_at \
                 FROM space_bans WHERE space_id = ?1 ORDER BY created_at",
            )
            .map_err(db_err)?;
        let rows: Vec<BanRow> = stmt
            .query_map(params![space_id], |row| {
                Ok(BanRow {
                    id: row.get(0)?,
                    space_id: row.get(1)?,
                    user_id: row.get(2)?,
                    banned_by: row.get(3)?,
                    reason: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                })
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows.into_iter().map(build_space_ban).collect())
    }

    /// Update a ban's reason and/or expiry.
    pub fn update_ban(
        &self,
        id: &str,
        reason: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "UPDATE space_bans SET reason = ?1, expires_at = ?2 WHERE id = ?3",
            params![reason, expires_at, id],
        )
        .map_err(db_err)?;
        let counter = crate::advance_state_counter_in_tx(&tx, "space_ban")?;
        tx.commit().map_err(db_err)?;
        self.emit("SpaceBan", format!("s-{counter}"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    /// Helper: open an in-memory store and return it.
    fn test_store() -> Store {
        Store::open_in_memory().expect("in-memory store must open")
    }

    // ── Space CRUD ──────────────────────────────────────────────────────

    #[test]
    fn create_space_roundtrip() {
        // Oracle: fields passed to create_space must match fields returned by get_space.
        let store = test_store();
        let ss = store.spaces();

        let space = ss
            .create_space(
                "sp-1",
                "Test Space",
                Some("A description"),
                Some("blob-icon"),
                true,
                false,
                1_700_000_000,
            )
            .expect("create_space");

        assert_eq!(space.id.as_ref(), "sp-1");
        assert_eq!(space.name, "Test Space");
        assert_eq!(space.description.as_deref(), Some("A description"));
        assert_eq!(
            space.icon_blob_id.as_ref().map(|id| id.as_ref()),
            Some("blob-icon")
        );
        assert!(space.is_public);
        assert!(!space.is_publicly_previewable);

        // Round-trip via get_space
        let fetched = ss.get_space("sp-1").unwrap().expect("space must exist");
        assert_eq!(fetched.id.as_ref(), "sp-1");
        assert_eq!(fetched.name, "Test Space");
        assert_eq!(fetched.description.as_deref(), Some("A description"));
        assert!(fetched.is_public);
        assert!(!fetched.is_publicly_previewable);
    }

    #[test]
    fn get_space_returns_none_for_nonexistent() {
        let store = test_store();
        let ss = store.spaces();
        let result = ss.get_space("no-such-space").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_spaces_empty_then_populated() {
        let store = test_store();
        let ss = store.spaces();

        // Oracle: empty store returns empty list.
        let empty = ss.list_spaces().unwrap();
        assert!(empty.is_empty());

        ss.create_space("sp-a", "Alpha", None, None, false, false, 1000)
            .unwrap();
        ss.create_space("sp-b", "Beta", None, None, false, false, 2000)
            .unwrap();

        let spaces = ss.list_spaces().unwrap();
        assert_eq!(spaces.len(), 2);
        // Oracle: ordered by created_at ASC.
        assert_eq!(spaces[0].id.as_ref(), "sp-a");
        assert_eq!(spaces[1].id.as_ref(), "sp-b");
    }

    #[test]
    fn update_space_metadata_persists() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-upd", "Original", None, None, false, false, 1000)
            .unwrap();

        ss.update_space_metadata("sp-upd", Some("Renamed"), Some(Some("New desc")), None)
            .unwrap();

        let fetched = ss.get_space("sp-upd").unwrap().expect("must exist");
        assert_eq!(fetched.name, "Renamed");
        assert_eq!(fetched.description.as_deref(), Some("New desc"));
    }

    #[test]
    fn delete_space_cascades() {
        // Oracle: DELETE CASCADE must remove roles, members, and their junction rows.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-del", "Doomed", None, None, false, false, 1000)
            .unwrap();
        ss.add_role("sp-del", "role-del", "Admin", None, &["manage"], 1)
            .unwrap();
        ss.add_member("sp-del", "user-del", None, 1000, &["role-del"])
            .unwrap();

        ss.delete_space("sp-del").unwrap();

        assert!(ss.get_space("sp-del").unwrap().is_none());

        // Verify cascade: roles and members gone.
        let roles = ss.load_roles("sp-del").unwrap();
        assert!(roles.is_empty());
        let members = ss.load_members("sp-del").unwrap();
        assert!(members.is_empty());
    }

    // ── SpaceRole CRUD ──────────────────────────────────────────────────

    #[test]
    fn add_role_and_load_roles_roundtrip() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-r1", "Roles Space", None, None, false, false, 1000)
            .unwrap();
        ss.add_role("sp-r1", "role-mod", "Moderator", Some("#00ff00"), &[], 1)
            .unwrap();

        let roles = ss.load_roles("sp-r1").unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id.as_ref(), "role-mod");
        assert_eq!(roles[0].name, "Moderator");
        assert_eq!(roles[0].color.as_deref(), Some("#00ff00"));
        assert_eq!(roles[0].position, 1);
    }

    #[test]
    fn add_role_with_permissions() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-rp", "Perms Space", None, None, false, false, 1000)
            .unwrap();
        ss.add_role(
            "sp-rp",
            "role-admin",
            "Admin",
            None,
            &["manage", "kick", "ban"],
            1,
        )
        .unwrap();

        let roles = ss.load_roles("sp-rp").unwrap();
        assert_eq!(roles.len(), 1);
        let perms = &roles[0].permissions;
        assert_eq!(perms.len(), 3);
        // Oracle: permissions sorted alphabetically by ORDER BY.
        assert!(perms.contains(&"ban".to_string()));
        assert!(perms.contains(&"kick".to_string()));
        assert!(perms.contains(&"manage".to_string()));
    }

    #[test]
    fn remove_role_cascades_member_roles() {
        // Oracle: deleting a role must cascade to space_member_roles.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-rr", "Remove Role", None, None, false, false, 1000)
            .unwrap();
        ss.add_role("sp-rr", "role-rm", "ToRemove", None, &[], 1)
            .unwrap();
        ss.add_member("sp-rr", "user-rr", None, 1000, &["role-rm"])
            .unwrap();

        // Pre-check: member has the role.
        let before = ss.get_member_role_ids("sp-rr", "user-rr").unwrap();
        assert_eq!(before.len(), 1);

        ss.remove_role("role-rm").unwrap();

        // Role gone from space.
        let roles = ss.load_roles("sp-rr").unwrap();
        assert!(roles.is_empty());

        // Member role assignment also gone (CASCADE).
        let after = ss.get_member_role_ids("sp-rr", "user-rr").unwrap();
        assert!(after.is_empty());
    }

    #[test]
    fn update_role_changes_name_and_permissions() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-ur", "Update Role", None, None, false, false, 1000)
            .unwrap();
        ss.add_role("sp-ur", "role-ur", "Old", Some("#ff0000"), &["perm-a"], 1)
            .unwrap();

        ss.update_role(
            "role-ur",
            Some("New"),
            Some(Some("#0000ff")),
            Some(&["perm-b", "perm-c"]),
            Some(2),
        )
        .unwrap();

        let roles = ss.load_roles("sp-ur").unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "New");
        assert_eq!(roles[0].color.as_deref(), Some("#0000ff"));
        assert_eq!(roles[0].position, 2);
        assert_eq!(roles[0].permissions.len(), 2);
        assert!(roles[0].permissions.contains(&"perm-b".to_string()));
        assert!(roles[0].permissions.contains(&"perm-c".to_string()));
    }

    // ── SpaceMember CRUD ────────────────────────────────────────────────

    #[test]
    fn add_member_and_load_members_roundtrip() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-m1", "Members", None, None, false, false, 1000)
            .unwrap();
        ss.add_member("sp-m1", "user-alice", Some("Alice"), 1_700_000_000, &[])
            .unwrap();

        let members = ss.load_members("sp-m1").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].id.as_ref(), "user-alice");
        assert_eq!(members[0].nick.as_deref(), Some("Alice"));
        // Oracle: 1700000000 = 2023-11-14T22:13:20Z
        assert_eq!(members[0].joined_at.as_ref(), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn add_member_with_roles() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-mr", "MemberRoles", None, None, false, false, 1000)
            .unwrap();
        ss.add_role("sp-mr", "role-a", "A", None, &[], 1).unwrap();
        ss.add_role("sp-mr", "role-b", "B", None, &[], 2).unwrap();

        ss.add_member("sp-mr", "user-bob", None, 1000, &["role-a", "role-b"])
            .unwrap();

        let role_ids = ss.get_member_role_ids("sp-mr", "user-bob").unwrap();
        assert_eq!(role_ids.len(), 2);
        assert!(role_ids.contains(&"role-a".to_string()));
        assert!(role_ids.contains(&"role-b".to_string()));
    }

    #[test]
    fn remove_member() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-rm", "RemoveMember", None, None, false, false, 1000)
            .unwrap();
        ss.add_role("sp-rm", "role-rm2", "R", None, &[], 1).unwrap();
        ss.add_member("sp-rm", "user-rm", None, 1000, &["role-rm2"])
            .unwrap();

        assert!(ss.is_member("sp-rm", "user-rm").unwrap());

        ss.remove_member("sp-rm", "user-rm").unwrap();

        assert!(!ss.is_member("sp-rm", "user-rm").unwrap());

        // member_roles cascade: no orphan rows.
        let role_ids = ss.get_member_role_ids("sp-rm", "user-rm").unwrap();
        assert!(role_ids.is_empty());
    }

    #[test]
    fn is_member_true_false() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-im", "IsMember", None, None, false, false, 1000)
            .unwrap();

        assert!(!ss.is_member("sp-im", "user-x").unwrap());

        ss.add_member("sp-im", "user-x", None, 1000, &[]).unwrap();
        assert!(ss.is_member("sp-im", "user-x").unwrap());
    }

    // ── State counter ───────────────────────────────────────────────────

    #[test]
    fn state_counter_advances_on_create_and_delete() {
        // Oracle: each mutation advances the space state counter by 1.
        let store = test_store();
        let ss = store.spaces();

        let s0 = ss.get_state().unwrap();
        assert_eq!(s0, "s-0");

        ss.create_space("sp-st1", "S1", None, None, false, false, 1000)
            .unwrap();
        let s1 = ss.get_state().unwrap();
        assert_eq!(s1, "s-1");

        ss.delete_space("sp-st1").unwrap();
        let s2 = ss.get_state().unwrap();
        assert_eq!(s2, "s-2");
    }

    #[test]
    fn state_counter_advances_on_add_role() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-src", "S", None, None, false, false, 1000)
            .unwrap();
        let before = ss.get_state().unwrap();

        ss.add_role("sp-src", "r1", "R", None, &[], 1).unwrap();
        let after = ss.get_state().unwrap();

        // Oracle: state must advance by exactly 1.
        let before_n: i64 = before.strip_prefix("s-").unwrap().parse().unwrap();
        let after_n: i64 = after.strip_prefix("s-").unwrap().parse().unwrap();
        assert_eq!(after_n, before_n + 1);
    }

    #[test]
    fn state_counter_advances_on_add_member() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-smc", "S", None, None, false, false, 1000)
            .unwrap();
        let before = ss.get_state().unwrap();

        ss.add_member("sp-smc", "user-1", None, 1000, &[]).unwrap();
        let after = ss.get_state().unwrap();

        let before_n: i64 = before.strip_prefix("s-").unwrap().parse().unwrap();
        let after_n: i64 = after.strip_prefix("s-").unwrap().parse().unwrap();
        assert_eq!(after_n, before_n + 1);
    }

    // ── get_changes_since ───────────────────────────────────────────────

    #[test]
    fn get_changes_since_no_changes() {
        let store = test_store();
        let ss = store.spaces();

        let (changed, destroyed, new_state) = ss.get_changes_since("s-0").unwrap();
        assert!(changed.is_empty());
        assert!(destroyed.is_empty());
        assert_eq!(new_state, "s-0");
    }

    #[test]
    fn get_changes_since_returns_created_space() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-gc", "Changed", None, None, false, false, 1000)
            .unwrap();

        let (changed, _destroyed, new_state) = ss.get_changes_since("s-0").unwrap();
        assert!(
            changed.contains(&"sp-gc".to_string()),
            "created space must appear in changed; got {:?}",
            changed
        );
        assert_eq!(new_state, "s-1");
    }

    #[test]
    fn get_changes_since_returns_updated_space() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-gu", "Before", None, None, false, false, 1000)
            .unwrap();
        let mid_state = ss.get_state().unwrap();

        ss.update_space_metadata("sp-gu", Some("After"), None, None)
            .unwrap();

        let (changed, _destroyed, _new_state) = ss.get_changes_since(&mid_state).unwrap();
        assert!(
            changed.contains(&"sp-gu".to_string()),
            "updated space must appear in changed; got {:?}",
            changed
        );
    }

    #[test]
    fn get_changes_since_malformed_state() {
        let store = test_store();
        let ss = store.spaces();
        let result = ss.get_changes_since("bad");
        assert!(result.is_err());
    }

    // ── update_member ───────────────────────────────────────────────────

    #[test]
    fn update_member_nick_and_roles() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-um", "UM", None, None, false, false, 1000)
            .unwrap();
        ss.add_role("sp-um", "role-x", "X", None, &[], 1).unwrap();
        ss.add_role("sp-um", "role-y", "Y", None, &[], 2).unwrap();
        ss.add_member("sp-um", "user-um", Some("OldNick"), 1000, &["role-x"])
            .unwrap();

        ss.update_member("sp-um", "user-um", Some(Some("NewNick")), Some(&["role-y"]))
            .unwrap();

        let members = ss.load_members("sp-um").unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].nick.as_deref(), Some("NewNick"));

        let role_ids = ss.get_member_role_ids("sp-um", "user-um").unwrap();
        assert_eq!(role_ids, vec!["role-y".to_string()]);
    }

    // ── Events emission ─────────────────────────────────────────────────

    #[test]
    fn create_space_emits_state_change() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(100);
        let mut store = test_store();
        store.set_events_tx(tx);
        let ss = store.spaces();

        ss.create_space("sp-ev", "Events", None, None, false, false, 1000)
            .unwrap();

        let change = rx
            .try_recv()
            .expect("StateChange must be emitted on create_space");
        assert_eq!(change.type_name, "Space");
        assert_eq!(change.new_state, ss.get_state().unwrap());
    }

    #[test]
    fn delete_space_emits_state_change() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(100);
        let mut store = test_store();
        store.set_events_tx(tx);
        let ss = store.spaces();

        ss.create_space("sp-ev2", "Del", None, None, false, false, 1000)
            .unwrap();
        let _ = rx.try_recv(); // drain create event

        ss.delete_space("sp-ev2").unwrap();

        let change = rx
            .try_recv()
            .expect("StateChange must be emitted on delete_space");
        assert_eq!(change.type_name, "Space");
    }

    // ── get_space loads roles and members ────────────────────────────────

    #[test]
    fn get_space_loads_roles_and_members() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("sp-full", "Full", None, None, false, false, 1000)
            .unwrap();
        ss.add_role("sp-full", "r-full", "Admin", Some("#red"), &["manage"], 1)
            .unwrap();
        ss.add_member("sp-full", "u-full", Some("Nick"), 1000, &["r-full"])
            .unwrap();

        let space = ss.get_space("sp-full").unwrap().expect("must exist");
        assert_eq!(space.roles.len(), 1);
        assert_eq!(space.roles[0].id.as_ref(), "r-full");
        assert_eq!(space.roles[0].permissions, vec!["manage".to_string()]);

        assert_eq!(space.members.len(), 1);
        assert_eq!(space.members[0].id.as_ref(), "u-full");
        assert_eq!(space.members[0].nick.as_deref(), Some("Nick"));
        assert_eq!(space.member_count, 1);
    }

    // ── update_space_metadata clears description ────────────────────────

    #[test]
    fn update_space_metadata_clears_description() {
        let store = test_store();
        let ss = store.spaces();

        ss.create_space(
            "sp-clr",
            "Clear",
            Some("has desc"),
            None,
            false,
            false,
            1000,
        )
        .unwrap();

        // Set description to NULL.
        ss.update_space_metadata("sp-clr", None, Some(None), None)
            .unwrap();

        let fetched = ss.get_space("sp-clr").unwrap().expect("must exist");
        assert!(fetched.description.is_none());
    }

    // ── Category tests ──────────────────────────────────────────────────

    #[test]
    fn add_and_load_category() {
        // Oracle: inserted category must be loadable with correct fields.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.add_category("space-1", "cat-1", "General", 0).unwrap();

        let cats = ss.load_categories("space-1").unwrap();
        assert_eq!(cats.len(), 1);
        assert_eq!(cats[0].id.as_ref(), "cat-1");
        assert_eq!(cats[0].name, "General");
        assert_eq!(cats[0].position, 0);
        assert!(cats[0].channel_ids.is_empty());
    }

    #[test]
    fn load_categories_with_channel_ids() {
        // Oracle: channels assigned to a category appear in channel_ids.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();

        // Create chat rows first (FK target for category_channels).
        store
            .chats()
            .create("ch-1", "channel", None, 1000)
            .unwrap();
        store
            .chats()
            .create("ch-2", "channel", None, 1001)
            .unwrap();

        ss.add_category("space-1", "cat-1", "General", 0).unwrap();
        ss.assign_channel_to_category("cat-1", "ch-1", 0).unwrap();
        ss.assign_channel_to_category("cat-1", "ch-2", 1).unwrap();

        let cats = ss.load_categories("space-1").unwrap();
        assert_eq!(cats.len(), 1);
        let ch_ids: Vec<&str> = cats[0].channel_ids.iter().map(|id| id.as_ref()).collect();
        assert_eq!(ch_ids, vec!["ch-1", "ch-2"]);
    }

    #[test]
    fn remove_category_cascades_channel_assignments() {
        // Oracle: ON DELETE CASCADE removes category_channels rows.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();

        store
            .chats()
            .create("ch-c1", "channel", None, 1000)
            .unwrap();

        ss.add_category("space-1", "cat-del", "Temp", 0).unwrap();
        ss.assign_channel_to_category("cat-del", "ch-c1", 0)
            .unwrap();

        ss.remove_category("cat-del").unwrap();

        // Category gone.
        let cats = ss.load_categories("space-1").unwrap();
        assert!(cats.is_empty());

        // category_channels row also gone.
        let count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM category_channels WHERE category_id = 'cat-del'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "cascade must remove category_channels rows");
    }

    #[test]
    fn update_category_changes_name_and_position() {
        // Oracle: after update, name and position reflect new values.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.add_category("space-1", "cat-upd", "Old", 0).unwrap();
        ss.update_category("cat-upd", "New", 5).unwrap();

        let cats = ss.load_categories("space-1").unwrap();
        assert_eq!(cats[0].name, "New");
        assert_eq!(cats[0].position, 5);
    }

    // ── Channel tests ───────────────────────────────────────────────────

    #[test]
    fn create_channel_sets_space_id_and_kind() {
        // Oracle: UPDATE must set space_id, kind='channel', and name on the chat row.
        let store = test_store();

        store
            .spaces()
            .create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();

        // Create a plain chat first.
        store.chats().create("ch-ch1", "direct", None, 1000).unwrap();

        store
            .spaces()
            .create_channel("space-1", "ch-ch1", "general")
            .unwrap();

        // Verify via direct SQL (the Chat type may not expose space_id yet).
        let (kind, space_id, name): (String, Option<String>, Option<String>) = store
            .conn
            .query_row(
                "SELECT kind, space_id, name FROM chats WHERE id = 'ch-ch1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(kind, "channel");
        assert_eq!(space_id.as_deref(), Some("space-1"));
        assert_eq!(name.as_deref(), Some("general"));
    }

    #[test]
    fn uncategorized_channels() {
        // Oracle: channels with space_id but not in any category are uncategorized.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-u", "SpaceU", None, None, false, false, 1000)
            .unwrap();

        store
            .chats()
            .create("ch-unc1", "channel", None, 1000)
            .unwrap();
        store
            .chats()
            .create("ch-unc2", "channel", None, 1001)
            .unwrap();
        store
            .chats()
            .create("ch-cat1", "channel", None, 1002)
            .unwrap();

        ss.create_channel("space-u", "ch-unc1", "uncategorized-1")
            .unwrap();
        ss.create_channel("space-u", "ch-unc2", "uncategorized-2")
            .unwrap();
        ss.create_channel("space-u", "ch-cat1", "categorized")
            .unwrap();

        // Put ch-cat1 in a category.
        ss.add_category("space-u", "cat-u1", "General", 0)
            .unwrap();
        ss.assign_channel_to_category("cat-u1", "ch-cat1", 0)
            .unwrap();

        let uncat = ss.get_uncategorized_channel_ids("space-u").unwrap();
        assert_eq!(uncat.len(), 2);
        assert!(uncat.contains(&"ch-unc1".to_string()));
        assert!(uncat.contains(&"ch-unc2".to_string()));
        assert!(!uncat.contains(&"ch-cat1".to_string()));
    }

    // ── Permission override tests ───────────────────────────────────────

    #[test]
    fn set_and_load_permission_overrides() {
        // Oracle: set_channel_permission_overrides + load round-trip.
        let store = test_store();
        let ss = store.spaces();

        store
            .chats()
            .create("ch-perm1", "channel", None, 1000)
            .unwrap();

        let overrides = vec![
            make_channel_permission(
                "role-1",
                "role",
                vec!["send_message".to_string()],
                vec!["ban".to_string()],
            ),
            make_channel_permission(
                "user-1",
                "member",
                vec!["read_messages".to_string()],
                vec![],
            ),
        ];

        ss.set_channel_permission_overrides("ch-perm1", &overrides)
            .unwrap();

        let loaded = ss.load_channel_permission_overrides("ch-perm1").unwrap();
        assert_eq!(loaded.len(), 2);

        // Find role-1 override.
        let role_override = loaded
            .iter()
            .find(|p| p.target_id.as_ref() == "role-1")
            .expect("role-1 override must exist");
        assert_eq!(role_override.target_type, "role");
        assert_eq!(role_override.allow, vec!["send_message"]);
        assert_eq!(role_override.deny, vec!["ban"]);

        // Find user-1 override.
        let user_override = loaded
            .iter()
            .find(|p| p.target_id.as_ref() == "user-1")
            .expect("user-1 override must exist");
        assert_eq!(user_override.target_type, "member");
        assert_eq!(user_override.allow, vec!["read_messages"]);
        assert!(user_override.deny.is_empty());
    }

    #[test]
    fn set_permission_overrides_replaces_existing() {
        // Oracle: second call replaces all overrides from the first.
        let store = test_store();
        let ss = store.spaces();

        store
            .chats()
            .create("ch-perm2", "channel", None, 1000)
            .unwrap();

        let first = vec![make_channel_permission(
            "role-old",
            "role",
            vec!["a".to_string()],
            vec![],
        )];
        ss.set_channel_permission_overrides("ch-perm2", &first)
            .unwrap();

        let second = vec![make_channel_permission(
            "role-new",
            "role",
            vec!["b".to_string()],
            vec![],
        )];
        ss.set_channel_permission_overrides("ch-perm2", &second)
            .unwrap();

        let loaded = ss.load_channel_permission_overrides("ch-perm2").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].target_id.as_ref(), "role-new");
    }

    // ── SpaceInvite tests ───────────────────────────────────────────────

    #[test]
    fn create_and_get_invite() {
        // Oracle: created invite must be retrievable by ID with matching fields.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.create_invite(
            "inv-1",
            "CODE123",
            "space-1",
            "user-1",
            Some("ch-default"),
            Some(2_000_000_000),
            Some(100),
            1_000_000_000,
        )
        .unwrap();

        let invite = ss.get_invite("inv-1").unwrap().expect("invite must exist");
        assert_eq!(invite.id.as_ref(), "inv-1");
        assert_eq!(invite.code, "CODE123");
        assert_eq!(invite.space_id.as_ref(), "space-1");
        assert_eq!(invite.created_by.as_ref(), "user-1");
        assert_eq!(invite.uses, 0);
        assert_eq!(invite.max_uses, Some(100));
        assert!(invite.default_channel_id.is_some());
        assert!(invite.expires_at.is_some());
    }

    #[test]
    fn resolve_invite_by_code() {
        // Oracle: invite must be findable by its unique code.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.create_invite(
            "inv-2",
            "UNIQUE-CODE",
            "space-1",
            "user-1",
            None,
            None,
            None,
            1_000_000_000,
        )
        .unwrap();

        let invite = ss
            .resolve_invite_by_code("UNIQUE-CODE")
            .unwrap()
            .expect("invite must be found by code");
        assert_eq!(invite.id.as_ref(), "inv-2");
    }

    #[test]
    fn resolve_invite_by_code_not_found() {
        // Oracle: nonexistent code returns None.
        let store = test_store();
        let result = store
            .spaces()
            .resolve_invite_by_code("NO-SUCH-CODE")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn increment_invite_uses() {
        // Oracle: after increment, uses must be 1.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.create_invite(
            "inv-inc",
            "INC-CODE",
            "space-1",
            "user-1",
            None,
            None,
            None,
            1_000_000_000,
        )
        .unwrap();

        ss.increment_invite_uses("inv-inc").unwrap();

        let invite = ss.get_invite("inv-inc").unwrap().unwrap();
        assert_eq!(invite.uses, 1);
    }

    #[test]
    fn is_invite_valid_not_expired() {
        // Oracle: an invite with expires_at in the future is valid.
        let invite = SpaceInvite::new(
            Id::from("inv-v"),
            "CODE",
            Id::from("sp"),
            Id::from("u"),
            0,
            UTCDate::from("2026-01-01T00:00:00Z"),
            None,
            Some(UTCDate::from("2026-12-31T23:59:59Z")),
            Some(10),
        );
        // now_unix = 2026-06-01T00:00:00Z = 1780272000
        assert!(SpaceStore::is_invite_valid(&invite, 1_780_272_000));
    }

    #[test]
    fn is_invite_valid_expired() {
        // Oracle: an invite past its expires_at is invalid.
        let invite = SpaceInvite::new(
            Id::from("inv-exp"),
            "CODE",
            Id::from("sp"),
            Id::from("u"),
            0,
            UTCDate::from("2020-01-01T00:00:00Z"),
            None,
            Some(UTCDate::from("2020-06-01T00:00:00Z")),
            None,
        );
        // now_unix = 2021-01-01T00:00:00Z = 1609459200
        assert!(!SpaceStore::is_invite_valid(&invite, 1_609_459_200));
    }

    #[test]
    fn is_invite_valid_max_uses_exhausted() {
        // Oracle: an invite with uses >= max_uses is invalid.
        let invite = SpaceInvite::new(
            Id::from("inv-max"),
            "CODE",
            Id::from("sp"),
            Id::from("u"),
            10,
            UTCDate::from("2026-01-01T00:00:00Z"),
            None,
            None,
            Some(10),
        );
        assert!(!SpaceStore::is_invite_valid(&invite, 1_000_000));
    }

    #[test]
    fn is_invite_valid_no_constraints() {
        // Oracle: an invite with no expiry and no max_uses is always valid.
        let invite = SpaceInvite::new(
            Id::from("inv-nc"),
            "CODE",
            Id::from("sp"),
            Id::from("u"),
            5,
            UTCDate::from("2026-01-01T00:00:00Z"),
            None,
            None,
            None,
        );
        assert!(SpaceStore::is_invite_valid(&invite, 9_999_999_999));
    }

    #[test]
    fn delete_invite() {
        // Oracle: after delete, the invite must not be found.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.create_invite(
            "inv-del",
            "DEL-CODE",
            "space-1",
            "user-1",
            None,
            None,
            None,
            1_000_000_000,
        )
        .unwrap();

        ss.delete_invite("inv-del").unwrap();

        let result = ss.get_invite("inv-del").unwrap();
        assert!(result.is_none(), "deleted invite must not be found");
    }

    #[test]
    fn list_invites_for_space() {
        // Oracle: list must return all invites for a given space.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-list", "SpaceList", None, None, false, false, 1000)
            .unwrap();
        ss.create_space("space-other", "SpaceOther", None, None, false, false, 1001)
            .unwrap();
        ss.create_invite(
            "inv-l1",
            "CODE-L1",
            "space-list",
            "user-1",
            None,
            None,
            None,
            1_000_000_000,
        )
        .unwrap();
        ss.create_invite(
            "inv-l2",
            "CODE-L2",
            "space-list",
            "user-1",
            None,
            None,
            None,
            1_000_000_001,
        )
        .unwrap();
        // Different space -- must not appear.
        ss.create_invite(
            "inv-other",
            "CODE-OTHER",
            "space-other",
            "user-1",
            None,
            None,
            None,
            1_000_000_002,
        )
        .unwrap();

        let invites = ss.list_invites_for_space("space-list").unwrap();
        assert_eq!(invites.len(), 2);
        let ids: Vec<&str> = invites.iter().map(|i| i.id.as_ref()).collect();
        assert!(ids.contains(&"inv-l1"));
        assert!(ids.contains(&"inv-l2"));
    }

    #[test]
    fn invite_code_uniqueness() {
        // Oracle: UNIQUE constraint on code must reject duplicate codes.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.create_invite(
            "inv-u1",
            "SAME-CODE",
            "space-1",
            "user-1",
            None,
            None,
            None,
            1_000_000_000,
        )
        .unwrap();

        let result = ss.create_invite(
            "inv-u2",
            "SAME-CODE",
            "space-1",
            "user-1",
            None,
            None,
            None,
            1_000_000_001,
        );
        assert!(
            result.is_err(),
            "duplicate invite code must be rejected by UNIQUE constraint"
        );
    }

    // ── SpaceBan tests ──────────────────────────────────────────────────

    #[test]
    fn create_and_get_ban() {
        // Oracle: created ban must be retrievable by ID.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.create_ban(
            "ban-1",
            "space-1",
            "user-bad",
            "user-admin",
            Some("Spamming"),
            1_000_000_000,
            None,
        )
        .unwrap();

        let ban = ss.get_ban("ban-1").unwrap().expect("ban must exist");
        assert_eq!(ban.id.as_ref(), "ban-1");
        assert_eq!(ban.space_id.as_ref(), "space-1");
        assert_eq!(ban.user_id.as_ref(), "user-bad");
        assert_eq!(ban.banned_by.as_ref(), "user-admin");
        assert_eq!(ban.reason.as_deref(), Some("Spamming"));
        assert!(ban.expires_at.is_none());
    }

    #[test]
    fn is_banned_active_ban() {
        // Oracle: a ban without expiry is always active.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-b", "SpaceB", None, None, false, false, 1000)
            .unwrap();
        ss.create_ban(
            "ban-active",
            "space-b",
            "user-x",
            "admin",
            None,
            1_000_000_000,
            None,
        )
        .unwrap();

        assert!(ss.is_banned("space-b", "user-x", 2_000_000_000).unwrap());
    }

    #[test]
    fn is_banned_expired_ban_not_active() {
        // Oracle: a ban with expires_at in the past is not active.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-b", "SpaceB", None, None, false, false, 1000)
            .unwrap();
        ss.create_ban(
            "ban-exp",
            "space-b",
            "user-y",
            "admin",
            None,
            1_000_000_000,
            Some(1_500_000_000),
        )
        .unwrap();

        // now > expires_at
        assert!(!ss.is_banned("space-b", "user-y", 2_000_000_000).unwrap());
        // now < expires_at
        assert!(ss.is_banned("space-b", "user-y", 1_000_000_000).unwrap());
    }

    #[test]
    fn delete_ban_lifts_ban() {
        // Oracle: after delete, is_banned must return false.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-b", "SpaceB", None, None, false, false, 1000)
            .unwrap();
        ss.create_ban(
            "ban-lift",
            "space-b",
            "user-z",
            "admin",
            None,
            1_000_000_000,
            None,
        )
        .unwrap();

        assert!(ss.is_banned("space-b", "user-z", 2_000_000_000).unwrap());

        ss.delete_ban("ban-lift").unwrap();

        assert!(!ss.is_banned("space-b", "user-z", 2_000_000_000).unwrap());
    }

    #[test]
    fn list_bans_for_space() {
        // Oracle: list must return all bans for a given space.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-lb", "SpaceLB", None, None, false, false, 1000)
            .unwrap();
        ss.create_ban(
            "ban-lb1",
            "space-lb",
            "user-1",
            "admin",
            None,
            1_000_000_000,
            None,
        )
        .unwrap();
        ss.create_ban(
            "ban-lb2",
            "space-lb",
            "user-2",
            "admin",
            None,
            1_000_000_001,
            None,
        )
        .unwrap();

        let bans = ss.list_bans_for_space("space-lb").unwrap();
        assert_eq!(bans.len(), 2);
    }

    #[test]
    fn update_ban_changes_reason_and_expiry() {
        // Oracle: after update, reason and expires_at reflect new values.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();
        ss.create_ban(
            "ban-upd",
            "space-1",
            "user-u",
            "admin",
            Some("Original reason"),
            1_000_000_000,
            None,
        )
        .unwrap();

        ss.update_ban("ban-upd", Some("Updated reason"), Some(2_000_000_000))
            .unwrap();

        let ban = ss.get_ban("ban-upd").unwrap().unwrap();
        assert_eq!(ban.reason.as_deref(), Some("Updated reason"));
        assert!(ban.expires_at.is_some());
    }

    // ── State counter tests (invite/ban) ────────────────────────────────

    #[test]
    fn invite_create_advances_state_counter() {
        // Oracle: state counter for space_invite must advance on create.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();

        let before: i64 = store
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'space_invite'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        ss.create_invite(
            "inv-sc",
            "SC-CODE",
            "space-1",
            "user-1",
            None,
            None,
            None,
            1_000_000_000,
        )
        .unwrap();

        let after: i64 = store
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'space_invite'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(after > before, "state counter must advance on invite create");
    }

    #[test]
    fn ban_create_advances_state_counter() {
        // Oracle: state counter for space_ban must advance on create.
        let store = test_store();
        let ss = store.spaces();

        ss.create_space("space-1", "S1", None, None, false, false, 1000)
            .unwrap();

        let before: i64 = store
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'space_ban'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        ss.create_ban(
            "ban-sc",
            "space-1",
            "user-b",
            "admin",
            None,
            1_000_000_000,
            None,
        )
        .unwrap();

        let after: i64 = store
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'space_ban'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(after > before, "state counter must advance on ban create");
    }

    // ── parse_rfc3339_to_unix tests ─────────────────────────────────────

    #[test]
    fn parse_rfc3339_known_values() {
        // Oracle: cross-checked with kith_core::unix_secs_to_rfc3339 (independent direction).
        assert_eq!(parse_rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_to_unix("2001-09-09T01:46:40Z"), Some(1_000_000_000));
        assert_eq!(parse_rfc3339_to_unix("2020-06-01T00:00:00Z"), Some(1_590_969_600));
    }

    #[test]
    fn parse_rfc3339_rejects_invalid() {
        assert_eq!(parse_rfc3339_to_unix("not-a-date"), None);
        assert_eq!(parse_rfc3339_to_unix(""), None);
    }
}
