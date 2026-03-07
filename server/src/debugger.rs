use std::collections::{HashMap, HashSet};

use crate::condition::BreakpointCondition;
use crate::protocol::BreakpointEntry;

/// Tracks breakpoints set in the agent.
#[derive(Debug, Default)]
pub struct BreakpointManager {
    pub breakpoints: Vec<BreakpointEntry>,
    pub conditions: HashMap<i32, BreakpointCondition>,
    /// IDs of breakpoints that are queued on the agent waiting for class load.
    pub pending_ids: HashSet<i32>,
}

impl BreakpointManager {
    pub fn add(&mut self, bp: BreakpointEntry) {
        self.breakpoints.push(bp);
    }

    /// Update an existing entry by id if found, otherwise add as new.
    /// Returns true if an existing pending entry was updated (deferred → active).
    pub fn update_or_add(&mut self, bp: BreakpointEntry) -> bool {
        let was_pending = self.pending_ids.remove(&bp.id);
        if let Some(existing) = self.breakpoints.iter_mut().find(|b| b.id == bp.id) {
            *existing = bp;
            return was_pending;
        }
        self.breakpoints.push(bp);
        false
    }

    /// Add a placeholder entry for a deferred (class-not-yet-loaded) breakpoint.
    pub fn add_pending(&mut self, bp: BreakpointEntry) {
        self.pending_ids.insert(bp.id);
        self.breakpoints.push(bp);
    }

    pub fn is_pending(&self, id: i32) -> bool {
        self.pending_ids.contains(&id)
    }

    pub fn remove(&mut self, id: i32) {
        self.breakpoints.retain(|bp| bp.id != id);
        self.conditions.remove(&id);
        self.pending_ids.remove(&id);
    }

    pub fn replace_all(&mut self, bps: Vec<BreakpointEntry>) {
        // Keep conditions for breakpoints that still exist
        let valid_ids: HashSet<i32> = bps.iter().map(|bp| bp.id).collect();
        self.conditions.retain(|id, _| valid_ids.contains(id));
        self.pending_ids.retain(|id| valid_ids.contains(id));
        self.breakpoints = bps;
    }

    pub fn count(&self) -> usize {
        self.breakpoints.len()
    }

    pub fn set_condition(&mut self, bp_id: i32, cond: BreakpointCondition) {
        self.conditions.insert(bp_id, cond);
    }

    pub fn get_condition(&self, bp_id: i32) -> Option<&BreakpointCondition> {
        self.conditions.get(&bp_id)
    }

    /// Increment hit count for a breakpoint, returning the new count.
    pub fn increment_hit(&mut self, bp_id: i32) -> u32 {
        if let Some(cond) = self.conditions.get_mut(&bp_id) {
            cond.hit_count += 1;
            cond.hit_count
        } else {
            0
        }
    }
}
