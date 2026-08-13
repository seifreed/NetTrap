use super::*;

impl RedisHandler {
    pub(crate) fn client_name(&self) -> Option<String> {
        self.client_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn set_client_name(&self, name: Option<String>) {
        *self
            .client_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = name;
    }

    pub(crate) fn client_lib_name(&self) -> Option<String> {
        self.client_lib_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn client_lib_ver(&self) -> Option<String> {
        self.client_lib_ver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn set_client_lib_name(&self, value: Option<String>) {
        *self
            .client_lib_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn set_client_lib_ver(&self, value: Option<String>) {
        *self
            .client_lib_ver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn current_reply_mode(&self) -> ClientReplyMode {
        *self
            .client_reply_mode
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn current_state(&self) -> RedisState {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn set_state(&self, state: RedisState) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = state;
    }

    pub(crate) fn set_reply_mode(&self, mode: ClientReplyMode) {
        *self
            .client_reply_mode
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = mode;
    }

    pub(crate) fn set_client_no_evict(&self, value: bool) {
        *self
            .client_no_evict
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn set_client_no_touch(&self, value: bool) {
        *self
            .client_no_touch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_enabled(&self) -> bool {
        *self
            .client_tracking_enabled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_client_tracking_enabled(&self, value: bool) {
        *self
            .client_tracking_enabled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_bcast(&self) -> bool {
        *self
            .client_tracking_bcast
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_client_tracking_bcast(&self, value: bool) {
        *self
            .client_tracking_bcast
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_optin(&self) -> bool {
        *self
            .client_tracking_optin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_client_tracking_optin(&self, value: bool) {
        *self
            .client_tracking_optin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_optout(&self) -> bool {
        *self
            .client_tracking_optout
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_client_tracking_optout(&self, value: bool) {
        *self
            .client_tracking_optout
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_noloop(&self) -> bool {
        *self
            .client_tracking_noloop
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_client_tracking_noloop(&self, value: bool) {
        *self
            .client_tracking_noloop
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_redirect(&self) -> i64 {
        *self
            .client_tracking_redirect
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_client_tracking_redirect(&self, value: i64) {
        *self
            .client_tracking_redirect
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_prefixes(&self) -> Vec<String> {
        self.client_tracking_prefixes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn set_client_tracking_prefixes(&self, value: Vec<String>) {
        *self
            .client_tracking_prefixes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_caching(&self) -> Option<bool> {
        *self
            .client_tracking_caching
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_client_tracking_caching(&self, value: Option<bool>) {
        *self
            .client_tracking_caching
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_tracking_broken_redir(&self) -> bool {
        *self
            .client_tracking_broken_redir
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_client_tracking_broken_redir(&self, value: bool) {
        *self
            .client_tracking_broken_redir
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn resp_version(&self) -> u8 {
        *self
            .resp_version
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_resp_version(&self, value: u8) {
        *self
            .resp_version
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
    }

    pub(crate) fn client_no_evict(&self) -> bool {
        *self
            .client_no_evict
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn client_no_touch(&self) -> bool {
        *self
            .client_no_touch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn client_flags(&self) -> String {
        let mut flags = String::new();
        if self.client_no_evict() {
            flags.push('e');
        }
        if self.client_tracking_enabled() {
            flags.push('t');
        }
        if self.client_no_touch() {
            flags.push('T');
        }
        if self.client_tracking_broken_redir() {
            flags.push('R');
        }
        if self.client_tracking_bcast() {
            flags.push('B');
        }
        if flags.is_empty() {
            flags.push('N');
        }
        flags
    }
}
