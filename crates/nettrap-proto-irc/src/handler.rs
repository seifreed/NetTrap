use async_trait::async_trait;
use crate::prelude::*;

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
        resp.add(format!(":{} 001 {} :Welcome to the {} IRC Network {}!user@host\r\n", srv, nick, self.network_name, nick));
        resp.add(format!(":{} 002 {} :Your host is {}, running version nettrap-0.1.0\r\n", srv, nick, srv));
        resp.add(format!(":{} 003 {} :This server was created Mon Jan 1 2024 at 00:00:00 UTC\r\n", srv, nick));
        resp.add(format!(":{} 004 {} {} nettrap-0.1.0 iowghraAsORTVSxNCWqBzvdHtGpI lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGjZ\r\n", srv, nick, srv));
        resp.add(format!(":{} 375 {} :- {} Message of the Day -\r\n", srv, nick, srv));
        resp.add(format!(":{} 372 {} :- Welcome to NetTrap IRC honeypot\r\n", srv, nick));
        resp.add(format!(":{} 376 {} :End of /MOTD command.\r\n", srv, nick));
        resp
    }
}

impl Default for IrcHandler {
    fn default() -> Self { Self::new() }
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
                Ok(self.welcome_sequence(nick))
            }
            "PING" => {
                Ok(IrcResponse::single(format!(":{} PONG {} :{}\r\n", srv, srv, args)))
            }
            "PONG" => {
                Ok(IrcResponse::new())
            }
            "JOIN" => {
                let channel = if args.is_empty() { &self.channel } else { args.split(',').next().unwrap_or(&self.channel) };
                let mut resp = IrcResponse::new();
                resp.add(format!(":{}!user@host JOIN :{}\r\n", nick, channel));
                resp.add(format!(":{} 332 {} {} :Welcome to NetTrap\r\n", srv, nick, channel));
                resp.add(format!(":{} 353 {} = {} :@{} nettrap-bot\r\n", srv, nick, channel, nick));
                resp.add(format!(":{} 366 {} {} :End of /NAMES list.\r\n", srv, nick, channel));
                Ok(resp)
            }
            "PART" => {
                let channel = if args.is_empty() { &self.channel } else { args.split(' ').next().unwrap_or(&self.channel) };
                Ok(IrcResponse::single(format!(":{}!user@host PART {}\r\n", nick, channel)))
            }
            "PRIVMSG" => {
                tracing::debug!("IRC PRIVMSG from {}: {}", nick, args);
                Ok(IrcResponse::new())
            }
            "NOTICE" => {
                Ok(IrcResponse::new())
            }
            "MODE" => {
                if args.starts_with('#') || args.starts_with('&') {
                    Ok(IrcResponse::single(format!(":{} 324 {} {} +nt\r\n", srv, nick, args.split(' ').next().unwrap_or(args))))
                } else {
                    Ok(IrcResponse::single(format!(":{} 221 {} +i\r\n", srv, nick)))
                }
            }
            "WHO" => {
                let target = if args.is_empty() { "*" } else { args.split(' ').next().unwrap_or("*") };
                let mut resp = IrcResponse::new();
                resp.add(format!(":{} 352 {} {} user host {} nettrap-bot H :0 NetTrap Bot\r\n", srv, nick, target, srv));
                resp.add(format!(":{} 315 {} {} :End of /WHO list.\r\n", srv, nick, target));
                Ok(resp)
            }
            "WHOIS" => {
                let target = if args.is_empty() { nick } else { args.split(' ').next().unwrap_or(nick) };
                let mut resp = IrcResponse::new();
                resp.add(format!(":{} 311 {} {} user host * :NetTrap User\r\n", srv, nick, target));
                resp.add(format!(":{} 312 {} {} {} :NetTrap IRC\r\n", srv, nick, target, srv));
                resp.add(format!(":{} 318 {} {} :End of /WHOIS list.\r\n", srv, nick, target));
                Ok(resp)
            }
            "LIST" => {
                let mut resp = IrcResponse::new();
                resp.add(format!(":{} 321 {} Channel :Users  Name\r\n", srv, nick));
                resp.add(format!(":{} 322 {} {} 2 :Welcome to NetTrap\r\n", srv, nick, self.channel));
                resp.add(format!(":{} 323 {} :End of /LIST\r\n", srv, nick));
                Ok(resp)
            }
            "QUIT" => {
                Ok(IrcResponse::single(format!(":{} ERROR :Closing Link: {} (Quit: {})\r\n", srv, nick, args)))
            }
            "CAP" => {
                // CAP negotiation - respond with empty capabilities
                if args.to_uppercase().starts_with("LS") {
                    Ok(IrcResponse::single(format!(":{} CAP * LS :\r\n", srv)))
                } else if args.to_uppercase().starts_with("END") {
                    Ok(IrcResponse::new())
                } else {
                    Ok(IrcResponse::new())
                }
            }
            _ => {
                Ok(IrcResponse::single(format!(":{} 421 {} {} :Unknown command\r\n", srv, nick, cmd)))
            }
        }
    }

    fn name(&self) -> &'static str {
        "irc"
    }
}
