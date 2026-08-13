use crate::prelude::*;
use async_trait::async_trait;

mod commands;
use commands::*;

pub struct IrcHandler {
    server_name: String,
    banner: IrcBanner,
    network_name: String,
    channel: String,
    /// Clock for the "server created" (003) timestamp. The caller may inject
    /// the FakeTime instant so it stays consistent with the daytime/time/HTTP
    /// services; defaults to the real clock at emit time.
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl IrcHandler {
    const DEFAULT_SERVER_NAME: &'static str = "irc.nettrap.local";
    const DEFAULT_NETWORK_NAME: &'static str = "NetTrapNet";
    const MAX_COMMAND_BYTES: usize = 512;

    pub fn new() -> Self {
        Self {
            server_name: Self::DEFAULT_SERVER_NAME.to_string(),
            banner: IrcBanner::Generic,
            network_name: Self::DEFAULT_NETWORK_NAME.to_string(),
            channel: "#nettrap".to_string(),
            created_at: None,
        }
    }

    /// Inject the clock used for the 003 "server created" timestamp (FakeTime).
    pub fn with_clock(mut self, now: chrono::DateTime<chrono::Utc>) -> Self {
        self.created_at = Some(now);
        self
    }

    pub fn with_server_name(mut self, name: impl Into<String>) -> Result<Self> {
        self.server_name = validate_irc_server_name(&name.into())?;
        Ok(self)
    }

    pub fn with_network_name(mut self, name: impl Into<String>) -> Result<Self> {
        self.network_name = validate_irc_network_name(&name.into())?;
        Ok(self)
    }

    pub fn get_welcome_banner(&self) -> String {
        self.banner.get_banner_at(
            &self.server_name,
            self.created_at.unwrap_or_else(chrono::Utc::now),
        )
    }

    fn welcome_sequence(&self, nick: &str) -> IrcResponse {
        let nick = safe_irc_token(nick, "*");
        let nick = nick.as_str();
        let srv = &self.server_name;
        let mut resp = IrcResponse::new();
        resp.add(format!(
            ":{} 001 {} :Welcome to the {} IRC Network {}!user@host\r\n",
            srv, nick, self.network_name, nick
        ));
        resp.add(format!(
            ":{} 002 {} :Your host is {}, running version {}\r\n",
            srv,
            nick,
            srv,
            env!("CARGO_PKG_VERSION")
        ));
        // Real ircd reports a concrete creation timestamp; a frozen date is a
        // honeypot tell, so render the (FakeTime-aware) clock instead.
        let created = self
            .created_at
            .unwrap_or_else(chrono::Utc::now)
            .format("%a %b %-d %Y at %H:%M:%S UTC");
        resp.add(format!(
            ":{} 003 {} :This server was created {}\r\n",
            srv, nick, created
        ));
        resp.add(format!(
            ":{} 004 {} {} {} iowghraAsORTVSxNCWqBzvdHtGpI lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGjZ\r\n",
            srv,
            nick,
            srv,
            env!("CARGO_PKG_VERSION")
        ));
        resp.add(format!(
            ":{} 375 {} :- {} Message of the Day -\r\n",
            srv, nick, srv
        ));
        resp.add(format!(
            ":{} 372 {} :- Welcome to NetTrap IRC honeypot\r\n",
            srv, nick
        ));
        resp.add(format!(":{} 376 {} :End of /MOTD command.\r\n", srv, nick));
        resp
    }
}

impl Default for IrcHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait IrcHandlerTrait: Send + Sync {
    async fn handle(&self, command: &str, nick: &str) -> Result<IrcResponse>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl IrcHandlerTrait for IrcHandler {
    async fn handle(&self, command: &str, nick: &str) -> Result<IrcResponse> {
        let nick = safe_irc_token(nick, "*");
        let nick = nick.as_str();
        let srv = &self.server_name;
        if command.len() > Self::MAX_COMMAND_BYTES {
            return Ok(IrcResponse::single(format!(
                ":{} 417 {} :Input line was too long\r\n",
                srv, nick
            )));
        }
        let Some(command) = irc_command_line(command) else {
            return Ok(IrcResponse::single(format!(
                ":{} 421 {} INVALID :Unknown command\r\n",
                srv, nick
            )));
        };

        let parts: Vec<&str> = command.splitn(2, ' ').collect();
        let cmd = parts[0].to_uppercase();
        let safe_cmd = safe_irc_token(&cmd, "UNKNOWN");
        let args = if parts.len() > 1 {
            parts[1].trim_matches([' ', '\t'])
        } else {
            ""
        };

        match cmd.as_str() {
            "NICK" => {
                Ok(IrcResponse::new()) // handled by state
            }
            "USER" => {
                if user_args_are_valid(args) {
                    Ok(self.welcome_sequence(nick))
                } else {
                    Ok(IrcResponse::single(format!(
                        ":{} 461 {} USER :Not enough parameters\r\n",
                        srv, nick
                    )))
                }
            }
            "PING" => {
                let message = if let Some(token) = first_arg(args) {
                    let token = safe_irc_token(token, "*");
                    format!(":{} PONG {} :{}\r\n", srv, srv, token)
                } else {
                    format!(":{} 409 {} :No origin specified\r\n", srv, nick)
                };
                Ok(IrcResponse::single(message))
            }
            "PONG" => Ok(IrcResponse::new()),
            "JOIN" => {
                if args.trim_matches([' ', '\t']).is_empty() {
                    return Ok(IrcResponse::single(format!(
                        ":{} 461 {} JOIN :Not enough parameters\r\n",
                        srv, nick
                    )));
                }
                let Some(channel) = args
                    .split(',')
                    .map(|part| part.trim_matches([' ', '\t']))
                    .find_map(parse_irc_channel_arg)
                else {
                    return Ok(IrcResponse::single(format!(
                        ":{} 476 {} :Bad Channel Mask\r\n",
                        srv, nick
                    )));
                };
                let mut resp = IrcResponse::new();
                resp.add(format!(":{}!user@host JOIN :{}\r\n", nick, channel));
                resp.add(format!(
                    ":{} 332 {} {} :Welcome to NetTrap\r\n",
                    srv, nick, channel
                ));
                resp.add(format!(
                    ":{} 353 {} = {} :@{} nettrap-bot\r\n",
                    srv, nick, channel, nick
                ));
                resp.add(format!(
                    ":{} 366 {} {} :End of /NAMES list.\r\n",
                    srv, nick, channel
                ));
                Ok(resp)
            }
            "PART" => {
                if args.trim_matches([' ', '\t']).is_empty() {
                    return Ok(IrcResponse::single(format!(
                        ":{} 461 {} PART :Not enough parameters\r\n",
                        srv, nick
                    )));
                }
                let Some(channel) = parse_irc_channel_arg(args) else {
                    return Ok(IrcResponse::single(format!(
                        ":{} 476 {} :Bad Channel Mask\r\n",
                        srv, nick
                    )));
                };
                Ok(IrcResponse::single(format!(
                    ":{}!user@host PART {}\r\n",
                    nick, channel
                )))
            }
            "PRIVMSG" => {
                let Some((target, message)) = privmsg_parts(args) else {
                    return Ok(IrcResponse::single(format!(
                        ":{} 411 {} :No recipient given (PRIVMSG)\r\n",
                        srv, nick
                    )));
                };
                if message.is_empty() {
                    return Ok(IrcResponse::single(format!(
                        ":{} 412 {} :No text to send\r\n",
                        srv, nick
                    )));
                }
                tracing::debug!(
                    "IRC PRIVMSG from {} to {}: {}",
                    nick,
                    safe_irc_token(target, "*"),
                    safe_irc_trailing(message, "")
                );
                Ok(IrcResponse::new())
            }
            "NOTICE" => Ok(IrcResponse::new()),
            "MODE" => {
                if args.starts_with('#') || args.starts_with('&') {
                    let Some(channel) = parse_irc_channel_arg(args) else {
                        return Ok(IrcResponse::single(format!(
                            ":{} 476 {} :Bad Channel Mask\r\n",
                            srv, nick
                        )));
                    };
                    Ok(IrcResponse::single(format!(
                        ":{} 324 {} {} +nt\r\n",
                        srv, nick, channel
                    )))
                } else {
                    Ok(IrcResponse::single(format!(":{} 221 {} +i\r\n", srv, nick)))
                }
            }
            "WHO" => {
                let target = if args.is_empty() {
                    "*".to_string()
                } else {
                    let Some(raw_target) = first_arg(args) else {
                        return Ok(IrcResponse::single(format!(
                            ":{} 409 {} :No origin specified\r\n",
                            srv, nick
                        )));
                    };
                    if args.split_whitespace().nth(1).is_some() {
                        return Ok(IrcResponse::single(format!(
                            ":{} 461 {} WHO :Not enough parameters\r\n",
                            srv, nick
                        )));
                    }
                    if !is_valid_irc_token(raw_target) {
                        return Ok(IrcResponse::single(format!(
                            ":{} 461 {} WHO :Not enough parameters\r\n",
                            srv, nick
                        )));
                    }
                    safe_irc_token(raw_target, "*")
                };
                let mut resp = IrcResponse::new();
                resp.add(format!(
                    ":{} 352 {} {} user host {} nettrap-bot H :0 NetTrap Bot\r\n",
                    srv, nick, target, srv
                ));
                resp.add(format!(
                    ":{} 315 {} {} :End of /WHO list.\r\n",
                    srv, nick, target
                ));
                Ok(resp)
            }
            "WHOIS" => {
                let Some(target) = first_arg(args) else {
                    return Ok(IrcResponse::single(format!(
                        ":{} 431 {} :No nickname given\r\n",
                        srv, nick
                    )));
                };
                if args.split_whitespace().nth(1).is_some() {
                    return Ok(IrcResponse::single(format!(
                        ":{} 461 {} WHOIS :Not enough parameters\r\n",
                        srv, nick
                    )));
                }
                if !is_valid_irc_token(target) {
                    return Ok(IrcResponse::single(format!(
                        ":{} 461 {} WHOIS :Not enough parameters\r\n",
                        srv, nick
                    )));
                }
                let target = safe_irc_token(target, "*");
                let mut resp = IrcResponse::new();
                resp.add(format!(
                    ":{} 311 {} {} user host * :NetTrap User\r\n",
                    srv, nick, target
                ));
                resp.add(format!(
                    ":{} 312 {} {} {} :NetTrap IRC\r\n",
                    srv, nick, target, srv
                ));
                resp.add(format!(
                    ":{} 318 {} {} :End of /WHOIS list.\r\n",
                    srv, nick, target
                ));
                Ok(resp)
            }
            "LIST" => {
                if args.split_whitespace().nth(2).is_some() {
                    return Ok(IrcResponse::single(format!(
                        ":{} 461 {} LIST :Not enough parameters\r\n",
                        srv, nick
                    )));
                }
                let channel = safe_irc_channel(&self.channel);
                let mut resp = IrcResponse::new();
                resp.add(format!(":{} 321 {} Channel :Users  Name\r\n", srv, nick));
                resp.add(format!(
                    ":{} 322 {} {} 2 :Welcome to NetTrap\r\n",
                    srv, nick, channel
                ));
                resp.add(format!(":{} 323 {} :End of /LIST\r\n", srv, nick));
                Ok(resp)
            }
            "QUIT" => {
                let reason =
                    safe_irc_trailing(args.strip_prefix(':').unwrap_or(args), "Client quit");
                Ok(IrcResponse::single(format!(
                    ":{} ERROR :Closing Link: {} (Quit: {})\r\n",
                    srv, nick, reason
                )))
            }
            "CAP" => {
                // CAP negotiation - respond with empty capabilities
                if is_cap_ls(args) {
                    Ok(IrcResponse::single(format!(":{} CAP * LS :\r\n", srv)))
                } else if first_arg(args)
                    .is_some_and(|subcommand| subcommand.eq_ignore_ascii_case("LS"))
                {
                    Ok(IrcResponse::single(format!(
                        ":{} 461 {} CAP :Not enough parameters\r\n",
                        srv, nick
                    )))
                } else {
                    Ok(IrcResponse::new())
                }
            }
            _ => Ok(IrcResponse::single(format!(
                ":{} 421 {} {} :Unknown command\r\n",
                srv, nick, safe_cmd
            ))),
        }
    }

    fn name(&self) -> &'static str {
        "irc"
    }
}

fn irc_command_line(command: &str) -> Option<&str> {
    if command.chars().any(|ch| ch == '\0') {
        return None;
    }
    if let Some(line) = command.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        return Some(line);
    }
    if command.ends_with(['\r', '\n']) {
        return None;
    }
    if command.chars().any(|ch| matches!(ch, '\r' | '\n')) {
        return None;
    }
    Some(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut cx = Context::from_waker(Waker::noop());
        let mut future = Pin::from(Box::new(future));
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn cap_ls_requires_exact_subcommand() {
        assert!(is_cap_ls("LS"));
        assert!(is_cap_ls("ls 302"));
        assert!(!is_cap_ls("LSXYZ"));
        assert!(!is_cap_ls(""));
    }

    #[test]
    fn cap_ls_rejects_unicode_whitespace_separators() {
        assert!(!is_cap_ls("LS\u{00a0}302"));
    }

    #[test]
    fn cap_ls_rejects_tab_separated_subcommands() {
        assert!(!is_cap_ls("LS\t302"));
    }

    #[test]
    fn cap_ls_rejects_extra_arguments() {
        assert!(!is_cap_ls("LS 302 extra"));
    }

    #[test]
    fn cap_ls_rejects_compressed_spaces() {
        assert!(!is_cap_ls("LS  302"));
    }

    #[test]
    fn user_requires_required_registration_parameters() {
        let handler = IrcHandler::new();

        let invalid = block_on(handler.handle("USER guest 0 *", "guest")).expect("USER response");
        assert_eq!(
            invalid.to_bytes(),
            b":irc.nettrap.local 461 guest USER :Not enough parameters\r\n"
        );

        let malformed =
            block_on(handler.handle("USER guest 0 * Guest User", "guest")).expect("USER response");
        assert_eq!(
            malformed.to_bytes(),
            b":irc.nettrap.local 461 guest USER :Not enough parameters\r\n"
        );

        let missing_colon =
            block_on(handler.handle("USER guest 0 * Guest", "guest")).expect("USER response");
        assert_eq!(
            missing_colon.to_bytes(),
            b":irc.nettrap.local 461 guest USER :Not enough parameters\r\n"
        );

        let valid =
            block_on(handler.handle("USER guest 0 * :Guest User", "guest")).expect("USER response");
        let bytes = valid.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains(" 001 guest "));
    }

    #[test]
    fn oversized_irc_commands_are_rejected_before_parsing() {
        let handler = IrcHandler::new();
        let command = format!(
            "USER guest 0 * :{}",
            "a".repeat(IrcHandler::MAX_COMMAND_BYTES)
        );

        let response = block_on(handler.handle(&command, "guest")).expect("USER response");

        assert_eq!(
            response.to_bytes(),
            b":irc.nettrap.local 417 guest :Input line was too long\r\n"
        );
    }

    #[test]
    fn user_accepts_multi_word_realname_without_collecting_all_words() {
        let handler = IrcHandler::new();

        let response = block_on(handler.handle("USER guest 0 * :Guest User Name", "guest"))
            .expect("USER response");

        assert!(String::from_utf8_lossy(&response.to_bytes()).contains(" 001 guest "));
    }

    #[test]
    fn user_rejects_tab_separated_registration_parameters() {
        let handler = IrcHandler::new();

        let response = block_on(handler.handle("USER guest\t0\t*\t:Guest User", "guest"))
            .expect("USER response");

        assert_eq!(
            response.to_bytes(),
            b":irc.nettrap.local 461 guest USER :Not enough parameters\r\n"
        );
    }

    #[test]
    fn user_rejects_unicode_whitespace_inside_registration_parameters() {
        let handler = IrcHandler::new();

        let response = block_on(handler.handle("USER guest 0 * :Guest\u{00a0}User", "guest"))
            .expect("USER response");

        assert_eq!(
            response.to_bytes(),
            b":irc.nettrap.local 461 guest USER :Not enough parameters\r\n"
        );
    }

    #[test]
    fn ping_requires_origin_token() {
        let handler = IrcHandler::new();

        let missing = block_on(handler.handle("PING", "guest")).expect("PING response");
        assert_eq!(
            missing.to_bytes(),
            b":irc.nettrap.local 409 guest :No origin specified\r\n"
        );

        let valid = block_on(handler.handle("PING token extra", "guest")).expect("PING response");
        assert_eq!(
            valid.to_bytes(),
            b":irc.nettrap.local PONG irc.nettrap.local :token\r\n"
        );

        let valid = block_on(handler.handle("PING token\r\n", "guest")).expect("PING response");
        assert_eq!(
            valid.to_bytes(),
            b":irc.nettrap.local PONG irc.nettrap.local :token\r\n"
        );
    }

    #[test]
    fn cap_ls_handler_rejects_malformed_extra_arguments() {
        let handler = IrcHandler::new();

        let response = block_on(handler.handle("CAP LS 302 extra", "guest")).expect("CAP response");

        assert_eq!(
            response.to_bytes(),
            b":irc.nettrap.local 461 guest CAP :Not enough parameters\r\n"
        );
    }

    #[test]
    fn who_rejects_extra_arguments() {
        let handler = IrcHandler::new();

        let response = block_on(handler.handle("WHO nick extra", "guest")).expect("WHO response");

        assert_eq!(
            response.to_bytes(),
            b":irc.nettrap.local 461 guest WHO :Not enough parameters\r\n"
        );
    }

    #[test]
    fn privmsg_requires_recipient_and_text() {
        let handler = IrcHandler::new();

        let missing_recipient =
            block_on(handler.handle("PRIVMSG", "guest")).expect("PRIVMSG response");
        assert_eq!(
            missing_recipient.to_bytes(),
            b":irc.nettrap.local 411 guest :No recipient given (PRIVMSG)\r\n"
        );

        for command in ["PRIVMSG #nettrap", "PRIVMSG #nettrap :"] {
            let missing_text =
                block_on(handler.handle(command, "guest")).expect("PRIVMSG response");
            assert_eq!(
                missing_text.to_bytes(),
                b":irc.nettrap.local 412 guest :No text to send\r\n",
                "{command}"
            );
        }

        let tab_separated = block_on(handler.handle("PRIVMSG #nettrap\t:hello", "guest"))
            .expect("PRIVMSG response");
        assert_eq!(
            tab_separated.to_bytes(),
            b":irc.nettrap.local 411 guest :No recipient given (PRIVMSG)\r\n"
        );
    }

    #[test]
    fn join_part_and_whois_require_targets() {
        let handler = IrcHandler::new();

        let join = block_on(handler.handle("JOIN", "guest")).expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 461 guest JOIN :Not enough parameters\r\n"
        );

        let part = block_on(handler.handle("PART", "guest")).expect("PART response");
        assert_eq!(
            part.to_bytes(),
            b":irc.nettrap.local 461 guest PART :Not enough parameters\r\n"
        );

        let whois = block_on(handler.handle("WHOIS", "guest")).expect("WHOIS response");
        assert_eq!(
            whois.to_bytes(),
            b":irc.nettrap.local 431 guest :No nickname given\r\n"
        );
    }

    #[test]
    fn join_and_part_reject_unicode_whitespace_only_targets() {
        let handler = IrcHandler::new();

        let join = block_on(handler.handle("JOIN \u{00a0}", "guest")).expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );

        let part = block_on(handler.handle("PART \u{00a0}", "guest")).expect("PART response");
        assert_eq!(
            part.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );
    }

    #[test]
    fn join_and_part_keep_ascii_whitespace_only_targets_as_missing_arguments() {
        let handler = IrcHandler::new();

        let join = block_on(handler.handle("JOIN   ", "guest")).expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 461 guest JOIN :Not enough parameters\r\n"
        );

        let part = block_on(handler.handle("PART \t", "guest")).expect("PART response");
        assert_eq!(
            part.to_bytes(),
            b":irc.nettrap.local 461 guest PART :Not enough parameters\r\n"
        );
    }

    #[test]
    fn join_and_part_reject_invalid_channel_names() {
        let handler = IrcHandler::new();

        let join = block_on(handler.handle("JOIN notachannel", "guest")).expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );

        let part = block_on(handler.handle("PART notachannel", "guest")).expect("PART response");
        assert_eq!(
            part.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );

        let join =
            block_on(handler.handle("JOIN notachannel,#safe", "guest")).expect("JOIN response");
        let join = String::from_utf8(join.to_bytes()).expect("IRC response should be UTF-8");
        assert!(join.contains("JOIN :#safe\r\n"));
        assert!(!join.contains("#nettrap"));

        let join = block_on(handler.handle("JOIN #safe\t#evil", "guest")).expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );

        let join =
            block_on(handler.handle("JOIN \u{00a0}#safe\u{00a0}", "guest")).expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );

        let join = block_on(handler.handle("JOIN #sa\u{200b}fe", "guest")).expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );
    }

    #[test]
    fn join_rejects_unicode_line_separators_in_channel_arguments() {
        let handler = IrcHandler::new();

        let join =
            block_on(handler.handle("JOIN #safe\u{2028}:evil", "guest")).expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );
    }

    #[test]
    fn whois_rejects_extra_targets() {
        let handler = IrcHandler::new();

        let response =
            block_on(handler.handle("WHOIS alice bob", "guest")).expect("WHOIS response");

        assert_eq!(
            response.to_bytes(),
            b":irc.nettrap.local 461 guest WHOIS :Not enough parameters\r\n"
        );
    }

    #[test]
    fn who_and_whois_reject_unicode_whitespace_in_targets() {
        let handler = IrcHandler::new();

        let who = block_on(handler.handle("WHO nick\u{00a0}", "guest")).expect("WHO response");
        assert_eq!(
            who.to_bytes(),
            b":irc.nettrap.local 461 guest WHO :Not enough parameters\r\n"
        );

        let whois =
            block_on(handler.handle("WHOIS nick\u{00a0}", "guest")).expect("WHOIS response");
        assert_eq!(
            whois.to_bytes(),
            b":irc.nettrap.local 461 guest WHOIS :Not enough parameters\r\n"
        );
    }

    #[test]
    fn who_whois_join_and_part_reject_oversized_targets() {
        let handler = IrcHandler::new();
        let long_nick = "a".repeat(65);
        let long_channel = format!("#{}", "a".repeat(64));

        let who =
            block_on(handler.handle(&format!("WHO {long_nick}"), "guest")).expect("WHO response");
        assert_eq!(
            who.to_bytes(),
            b":irc.nettrap.local 461 guest WHO :Not enough parameters\r\n"
        );

        let whois = block_on(handler.handle(&format!("WHOIS {long_nick}"), "guest"))
            .expect("WHOIS response");
        assert_eq!(
            whois.to_bytes(),
            b":irc.nettrap.local 461 guest WHOIS :Not enough parameters\r\n"
        );

        let join = block_on(handler.handle(&format!("JOIN {long_channel}"), "guest"))
            .expect("JOIN response");
        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );

        let part = block_on(handler.handle(&format!("PART {long_channel}"), "guest"))
            .expect("PART response");
        assert_eq!(
            part.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );
    }

    #[test]
    fn mode_rejects_tab_separated_channel_arguments() {
        let handler = IrcHandler::new();

        let response = block_on(handler.handle("MODE #safe\t+o", "guest")).expect("MODE response");

        assert_eq!(
            response.to_bytes(),
            b":irc.nettrap.local 476 guest :Bad Channel Mask\r\n"
        );
    }

    #[test]
    fn echoed_nick_and_targets_cannot_inject_response_lines() {
        let handler = IrcHandler::new();

        let join =
            block_on(handler.handle("JOIN #safe\r\n:evil PRIVMSG #x :owned", "guest\r\n:evil"))
                .expect("JOIN response");

        assert_eq!(
            join.to_bytes(),
            b":irc.nettrap.local 421 * INVALID :Unknown command\r\n"
        );

        let ping = block_on(handler.handle("PING token\r\nOPER root pass", "guest")).expect("PING");
        assert_eq!(
            ping.to_bytes(),
            b":irc.nettrap.local 421 guest INVALID :Unknown command\r\n"
        );
    }

    #[test]
    fn nick_with_whitespace_falls_back_to_placeholder() {
        let handler = IrcHandler::new();

        let welcome =
            block_on(handler.handle("USER guest 0 * :Guest User", "guest name")).expect("response");
        let text = String::from_utf8(welcome.to_bytes()).expect("IRC response should be UTF-8");

        assert!(text.contains("Welcome to the NetTrapNet IRC Network *!user@host"));
        assert!(!text.contains("guest name"));
    }

    #[test]
    fn nick_with_invalid_punctuation_falls_back_to_placeholder() {
        let handler = IrcHandler::new();

        let welcome =
            block_on(handler.handle("USER guest 0 * :Guest User", "guest!name")).expect("response");
        let text = String::from_utf8(welcome.to_bytes()).expect("IRC response should be UTF-8");

        assert!(text.contains("Welcome to the NetTrapNet IRC Network *!user@host"));
        assert!(!text.contains("guest!name"));
    }

    #[test]
    fn nick_with_unicode_line_separators_falls_back_to_placeholder() {
        let handler = IrcHandler::new();

        let welcome = block_on(handler.handle("USER guest 0 * :Guest User", "guest\u{2028}name"))
            .expect("response");
        let text = String::from_utf8(welcome.to_bytes()).expect("IRC response should be UTF-8");

        assert!(text.contains("Welcome to the NetTrapNet IRC Network *!user@host"));
        assert!(!text.contains("guest\u{2028}name"));
    }

    #[test]
    fn user_command_rejects_compressed_spaces() {
        let handler = IrcHandler::new();

        let response =
            block_on(handler.handle("USER guest  0 * :Guest User", "guest")).expect("response");

        assert_eq!(
            response.to_bytes(),
            b":irc.nettrap.local 461 guest USER :Not enough parameters\r\n"
        );
    }

    #[test]
    fn configured_identity_values_cannot_inject_response_lines() {
        assert!(
            IrcHandler::new()
                .with_server_name("irc.example\r\n:evil NOTICE AUTH :owned")
                .is_err()
        );
        assert!(
            IrcHandler::new()
                .with_network_name("NetTrapNet\r\n:evil 001 owned")
                .is_err()
        );
    }

    #[test]
    fn welcome_banner_is_stable_for_one_handler_instance() {
        let handler = IrcHandler::new().with_clock(chrono::Utc::now());
        let first = handler.get_welcome_banner();
        let second = handler.get_welcome_banner();

        assert_eq!(first, second);
    }

    #[test]
    fn welcome_sequence_uses_the_emit_time_by_default() {
        use std::time::Duration;

        let handler = IrcHandler::new();
        let first = block_on(handler.handle("USER guest 0 * :Guest User", "guest"))
            .expect("USER response")
            .to_bytes();
        std::thread::sleep(Duration::from_millis(1100));
        let second = block_on(handler.handle("USER guest 0 * :Guest User", "guest"))
            .expect("USER response")
            .to_bytes();

        assert_ne!(first, second);
    }

    #[test]
    fn welcome_sequence_uses_the_package_version() {
        let handler = IrcHandler::new();

        let welcome =
            block_on(handler.handle("USER guest 0 * :Guest User", "guest")).expect("USER response");
        let welcome = String::from_utf8(welcome.to_bytes()).expect("IRC response should be UTF-8");

        assert!(welcome.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn configured_identity_values_reject_unicode_line_separators() {
        assert!(
            IrcHandler::new()
                .with_server_name("irc.example\u{2028}:evil NOTICE AUTH :owned")
                .is_err()
        );
        assert!(
            IrcHandler::new()
                .with_network_name("NetTrapNet\u{2029}:evil 001 owned")
                .is_err()
        );
    }

    #[test]
    fn configured_server_name_rejects_invalid_punctuation() {
        assert!(
            IrcHandler::new()
                .with_server_name("irc.example><injected")
                .is_err()
        );
    }

    #[test]
    fn configured_server_name_rejects_leading_whitespace() {
        assert!(IrcHandler::new().with_server_name(" irc.example").is_err());
    }

    #[test]
    fn configured_server_name_rejects_underscores() {
        assert!(
            IrcHandler::new()
                .with_server_name("irc_example.local")
                .is_err()
        );
    }

    #[test]
    fn configured_network_name_rejects_invalid_punctuation() {
        assert!(
            IrcHandler::new()
                .with_network_name("NetTrapNet><injected")
                .is_err()
        );
    }

    #[test]
    fn configured_network_name_rejects_underscores() {
        assert!(
            IrcHandler::new()
                .with_network_name("NetTrapNet_example")
                .is_err()
        );
    }

    #[test]
    fn configured_network_name_rejects_leading_whitespace() {
        assert!(IrcHandler::new().with_network_name(" NetTrapNet").is_err());
    }

    #[test]
    fn configured_network_name_preserves_internal_spacing() {
        let handler = IrcHandler::new()
            .with_network_name("NetTrap  Network")
            .expect("valid IRC network name");

        let welcome =
            block_on(handler.handle("USER guest 0 * :Guest User", "guest")).expect("USER response");
        let welcome = String::from_utf8(welcome.to_bytes()).expect("IRC response should be UTF-8");

        assert!(welcome.contains("Welcome to the NetTrap  Network IRC Network"));
    }

    #[test]
    fn quit_reason_is_single_line() {
        let handler = IrcHandler::new();

        let quit = block_on(handler.handle("QUIT :bye\r\nERROR injected", "guest"))
            .expect("QUIT response");
        let quit = String::from_utf8(quit.to_bytes()).expect("IRC response should be UTF-8");

        assert!(!quit.contains("ERROR injected\r\n"));
        assert_eq!(quit.matches("\r\n").count(), 1);
    }

    #[test]
    fn quit_reason_preserves_repeated_spaces() {
        let handler = IrcHandler::new();

        let quit = block_on(handler.handle("QUIT :bye   bye", "guest")).expect("QUIT response");
        let quit = String::from_utf8(quit.to_bytes()).expect("IRC response should be UTF-8");

        assert!(quit.contains("Quit: bye   bye"));
    }

    #[test]
    fn quit_reason_rejects_unicode_whitespace() {
        let handler = IrcHandler::new();

        let quit =
            block_on(handler.handle("QUIT :bye\u{2028}bye", "guest")).expect("QUIT response");
        let quit = String::from_utf8(quit.to_bytes()).expect("IRC response should be UTF-8");

        assert!(quit.contains("Quit: bye bye"));
        assert!(!quit.contains('\u{2028}'));
    }

    #[test]
    fn quit_reason_whitespace_only_falls_back_to_default() {
        let handler = IrcHandler::new();

        let quit = block_on(handler.handle("QUIT :   \t", "guest")).expect("QUIT response");
        let quit = String::from_utf8(quit.to_bytes()).expect("IRC response should be UTF-8");

        assert!(quit.contains("Quit: Client quit"));
    }

    #[test]
    fn list_rejects_extra_parameters() {
        let handler = IrcHandler::new();

        let response =
            block_on(handler.handle("LIST #safe extra more", "guest")).expect("LIST response");
        let text = String::from_utf8(response.to_bytes()).expect("IRC response should be UTF-8");

        assert!(text.contains("461 guest LIST :Not enough parameters"));
    }

    #[test]
    fn logged_privmsg_args_are_single_line() {
        let args = safe_irc_trailing("#chan :hello\r\nERROR injected\x1b", "");

        assert_eq!(args, "#chan :hello  ERROR injected ");
        assert!(!args.chars().any(char::is_control));
    }
}
