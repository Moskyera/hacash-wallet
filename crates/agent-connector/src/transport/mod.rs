use crate::error::{ConnectorError, ConnectorResult};

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

/// Two independent gates are required: the crate feature and an explicit
/// runtime choice by the trusted desktop UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListenerPolicy {
    pub enabled: bool,
}

impl ListenerPolicy {
    pub fn require_enabled(self) -> ConnectorResult<()> {
        if !cfg!(feature = "listener") || !self.enabled {
            return Err(ConnectorError::ListenerDisabled);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_is_disabled_by_default() {
        assert_eq!(
            ListenerPolicy::default().require_enabled(),
            Err(ConnectorError::ListenerDisabled)
        );
    }
}
