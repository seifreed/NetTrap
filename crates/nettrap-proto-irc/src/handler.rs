use crate::prelude::*;
use async_trait::async_trait;

pub struct IrcHandler {
    server_name: String,
    banner: IrcBanner,
    network_name: String,
    channel: String,
}

impl IrcHandler {
    pub fn new() -> Self {
        Self {
            server_name: "irc.nettrap.local".to_string(),
            banner: IrcBanner::Generic,
            network_name: "NetTrapNet".to_string(),
            channel: "#nettrap".to_string(),
        }
    }

    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = name.into();
        self
    }

    pub fn with_banner(mut self, banner: IrcBanner) -> Self {
        self.banner = banner;
        self
    }

    pub fn with_network_name(mut self, name: impl Into<String>) -> Self {
        self.network_name = name.into();
        self
    }

    pub fn get_welcome_banner(&self) -> String {
        self.banner.get_banner(&self.server_name)
    }

    fn welcome_sequence(&self, nick: &str) -> IrcResponse {
        let srv = &self.server_name;
        let mut resp = IrcResponse::new();
        resp.add(format!(
            ":{} 001 {} :Welcome to the {} IRC Network {}!user@host\r\n",
            srv, nick, self.network_name, nick
        ));
        resp.add(format!(
            ":{} 002 {} :Your host is {}, running version nettrap-0.1.0\r\n",
            srv, nick, srv
        ));
        resp.add(format!(
            ":{} 003 {} :This server was created Mon Jan 1 2024 at 00:00:00 UTC\r\n",
            srv, nick
        ));
        resp.add(format!(":{} 004 {} {} nettrap-0.1.0 iowghraAsORTVSxNCWqBzvdHtGpI lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGjZ\r\n", srv, nick, srv));
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
        let parts: Vec<&str> = command.splitn(2, ' ').collect();
        let cmd = parts[0].to_uppercase();
        let args = if parts.len() > 1 { parts[1].trim() } else { "" };
        let srv = &self.server_name;

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
                    format!(":{} PONG {} :{}\r\n", srv, srv, token)
                } else {
                    format!(":{} 409 {} :No origin specified\r\n", srv, nick)
                };
                Ok(IrcResponse::single(message))
            }
            "PONG" => Ok(IrcResponse::new()),
            "JOIN" => {
                let Some(channel) = args
                    .split(',')
                    .map(str::trim)
                    .find(|channel| !channel.is_empty())
                else {
                    return Ok(IrcResponse::single(format!(
                        ":{} 461 {} JOIN :Not enough parameters\r\n",
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
                let Some(channel) = first_arg(args) else {
                    return Ok(IrcResponse::single(format!(
                        ":{} 461 {} PART :Not enough parameters\r\n",
                        srv, nick
                    )));
                };
                Ok(IrcResponse::single(format!(
                    ":{}!user@host PART {}\r\n",
                    nick, channel
                )))
            }
            "PRIVMSG" => {
                tracing::debug!("IRC PRIVMSG from {}: {}", nick, args);
                Ok(IrcResponse::new())
            }
            "NOTICE" => Ok(IrcResponse::new()),
            "MODE" => {
                if args.starts_with('#') || args.starts_with('&') {
                    Ok(IrcResponse::single(format!(
                        ":{} 324 {} {} +nt\r\n",
                        srv,
                        nick,
                        args.split(' ').next().unwrap_or(args)
                    )))
                } else {
                    Ok(IrcResponse::single(format!(":{} 221 {} +i\r\n", srv, nick)))
                }
            }
            "WHO" => {
                let target = if args.is_empty() {
                    "*"
                } else {
                    args.split(' ').next().unwrap_or("*")
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
                let mut resp = IrcResponse::new();
                resp.add(format!(":{} 321 {} Channel :Users  Name\r\n", srv, nick));
                resp.add(format!(
                    ":{} 322 {} {} 2 :Welcome to NetTrap\r\n",
                    srv, nick, self.channel
                ));
                resp.add(format!(":{} 323 {} :End of /LIST\r\n", srv, nick));
                Ok(resp)
            }
            "QUIT" => Ok(IrcResponse::single(format!(
                ":{} ERROR :Closing Link: {} (Quit: {})\r\n",
                srv, nick, args
            ))),
            "CAP" => {
                // CAP negotiation - respond with empty capabilities
                if is_cap_ls(args) {
                    Ok(IrcResponse::single(format!(":{} CAP * LS :\r\n", srv)))
                } else {
                    Ok(IrcResponse::new())
                }
            }
            _ => Ok(IrcResponse::single(format!(
                ":{} 421 {} {} :Unknown command\r\n",
                srv, nick, cmd
            ))),
        }
    }

    fn name(&self) -> &'static str {
        "irc"
    }
}

fn is_cap_ls(args: &str) -> bool {
    args.split_whitespace()
        .next()
        .is_some_and(|subcommand| subcommand.eq_ignore_ascii_case("LS"))
}

fn first_arg(args: &str) -> Option<&str> {
    args.split_whitespace().next()
}

fn user_args_are_valid(args: &str) -> bool {
    let mut parts = args.split_whitespace();
    (0..4).all(|_| parts.next().is_some_and(|part| !part.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
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
    fn user_requires_required_registration_parameters() {
        let handler = IrcHandler::new();

        let invalid = block_on(handler.handle("USER guest 0 *", "guest")).expect("USER response");
        assert_eq!(
            invalid.to_bytes(),
            b":irc.nettrap.local 461 guest USER :Not enough parameters\r\n"
        );

        let valid =
            block_on(handler.handle("USER guest 0 * :Guest User", "guest")).expect("USER response");
        let bytes = valid.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains(" 001 guest "));
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
}
