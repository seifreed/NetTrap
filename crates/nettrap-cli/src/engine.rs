use tokio::task::JoinHandle;

use crate::cli::Commands;
use crate::config::EngineConfig;

pub async fn handle_command(command: Commands, verbose: bool, config_path: Option<std::path::PathBuf>) -> crate::Result<()> {
    match command {
        Commands::Run(args) => {
            let engine = run_engine(&args, verbose, config_path).await?;
            engine.run().await
        }
        Commands::Config(args) => handle_config(&args, config_path),
        Commands::Pcap(args) => handle_pcap(&args, verbose),
        Commands::Report(args) => handle_report(&args),
        Commands::Status(args) => handle_status(&args),
        Commands::Test(args) => handle_test(&args),
    }
}

async fn run_engine(args: &crate::cli::RunArgs, _verbose: bool, config_path: Option<std::path::PathBuf>) -> crate::Result<Engine> {
    let mut config = if let Some(path) = config_path {
        EngineConfig::from_file(&path)?
    } else {
        let default_path = std::path::Path::new("/etc/nettrap/config.toml");
        if default_path.exists() {
            EngineConfig::from_file(default_path)?
        } else {
            EngineConfig::default()
        }
    };
    
    if !args.ports.is_empty() {
        config.listeners = args.ports.iter().enumerate().map(|(i, port)| {
            crate::config::ListenerConfig::new(&format!("listener_{}", i), *port)
        }).collect();
    }
    
    if let Some(ref output) = args.output {
        config.output_path = Some(output.to_string_lossy().to_string());
    }
    
    if args.pcap {
        config.pcap_enabled = true;
    }
    
    if let Some(ref pcap_path) = args.pcap_path {
        config.pcap_enabled = true;
        config.pcap_path = Some(pcap_path.to_string_lossy().to_string());
    }
    
    config.attribution_enabled = args.attribution;
    
    let engine = Engine::new(config)?;
    Ok(engine)
}

fn handle_config(args: &crate::cli::ConfigArgs, config_path: Option<std::path::PathBuf>) -> crate::Result<()> {
    if args.defaults {
        let config = EngineConfig::default();
        println!("{}", toml::to_string_pretty(&config).unwrap());
        return Ok(());
    }
    
    let config = if let Some(ref path) = config_path {
        EngineConfig::from_file(path)?
    } else if args.check {
        let files = std::fs::read_dir(".")?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "toml").unwrap_or(false))
            .map(|e| e.path())
            .collect::<Vec<_>>();
        
        for file in files {
            match EngineConfig::from_file(&file) {
                Ok(_) => println!("✓ {} is valid", file.display()),
                Err(e) => println!("✗ {} is invalid: {}", file.display(), e),
            }
        }
        return Ok(());
    } else {
        EngineConfig::default()
    };
    
    if let Some(ref output) = args.output {
        config.to_file(&output.to_string_lossy())?;
        println!("Config written to {}", output.display());
    } else {
        println!("{}", toml::to_string_pretty(&config).unwrap());
    }
    
    Ok(())
}

fn handle_pcap(args: &crate::cli::PcapArgs, _verbose: bool) -> crate::Result<()> {
    println!("Processing PCAP file: {}", args.input.display());
    Ok(())
}

fn handle_report(args: &crate::cli::ReportArgs) -> crate::Result<()> {
    println!("Generating report from: {}", args.input.display());
    Ok(())
}

fn handle_status(args: &crate::cli::StatusArgs) -> crate::Result<()> {
    if args.json {
        println!("{}", r#"{"status": "ok", "version": "0.1.0"}"#);
    } else {
        println!("NetTrap Status: OK");
        println!("Version: 0.1.0");
    }
    Ok(())
}

fn handle_test(_args: &crate::cli::TestArgs) -> crate::Result<()> {
    println!("Running tests...");
    Ok(())
}

pub struct Engine {
    config: EngineConfig,
}

impl Engine {
    pub fn new(config: EngineConfig) -> crate::Result<Self> {
        Ok(Self { config })
    }
    
    pub async fn run(&self) -> crate::Result<()> {
        tracing::info!("Starting NetTrap engine...");
        tracing::info!("Listeners: {}", self.config.listeners.len());
        
        let mut handles: Vec<JoinHandle<crate::Result<()>>> = Vec::new();
        
        for listener in &self.config.listeners {
            if !listener.enabled {
                continue;
            }
            
            tracing::info!("Starting listener {} on port {} ({:?})", 
                listener.name, listener.port, listener.protocol);
            
            let name = listener.name.clone();
            let port = listener.port;
            let protocol = listener.protocol.clone();
            let bind_addr: std::net::IpAddr = listener.bind_address.parse()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            
            match protocol {
                nettrap_core::prelude::Protocol::Udp => {
                    let handle = tokio::spawn(async move {
                        run_udp_listener(&name, port, bind_addr).await
                    });
                    handles.push(handle);
                }
                nettrap_core::prelude::Protocol::Tcp => {
                    let handle = tokio::spawn(async move {
                        run_tcp_listener(&name, port, bind_addr).await
                    });
                    handles.push(handle);
                }
                _ => {
                    tracing::warn!("Unsupported protocol {:?} for listener {}", protocol, name);
                }
            }
        }
        
        tracing::info!("Engine running with {} listeners", handles.len());
        
        tokio::signal::ctrl_c().await?;
        tracing::info!("Shutting down...");
        
        for handle in handles {
            handle.abort();
        }
        
        Ok(())
    }
    
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }
}

async fn run_udp_listener(name: &str, port: u16, bind_addr: std::net::IpAddr) -> crate::Result<()> {
    use tokio::net::UdpSocket;
    use nettrap_proto_dns::handler::DnsHandlerTrait;
    
    let addr = std::net::SocketAddr::new(bind_addr, port);
    let socket = UdpSocket::bind(addr).await?;
    
    tracing::info!("UDP listener '{}' listening on {}", name, addr);
    
    let dns_handler = nettrap_proto_dns::handler::DnsHandler::new();
    
    let mut buf = vec![0u8; 65535];
    
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                tracing::debug!("UDP listener '{}' received {} bytes from {}", name, len, src);
                
                let query_data = buf[..len].to_vec();
                
                match dns_handler.handle_query(&query_data, src).await {
                    Ok(response) => {
                        if let Err(e) = socket.send_to(&response, src).await {
                            tracing::warn!("Failed to send UDP response to {}: {}", src, e);
                        } else {
                            tracing::debug!("UDP listener '{}' sent {} bytes to {}", name, response.len(), src);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("UDP handler error from {}: {}", src, e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("UDP recv_from error: {}", e);
            }
        }
    }
}

async fn run_tcp_listener(name: &str, port: u16, bind_addr: std::net::IpAddr) -> crate::Result<()> {
    use tokio::net::TcpListener;
    
    let addr = std::net::SocketAddr::new(bind_addr, port);
    let listener = TcpListener::bind(addr).await?;
    
    tracing::info!("TCP listener '{}' listening on {}", name, addr);
    
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tracing::debug!("TCP listener '{}' accepted connection from {}", name, peer);
                
                let name_owned = name.to_string();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_connection(&name_owned, stream, peer).await {
                        tracing::debug!("TCP connection error from {}: {}", peer, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("TCP accept error: {}", e);
            }
        }
    }
}

async fn handle_tcp_connection(name: &str, mut stream: tokio::net::TcpStream, peer: std::net::SocketAddr) -> crate::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use nettrap_proto_smtp::SmtpHandlerTrait;
    
    tracing::debug!("TCP listener '{}' handling connection from {}", name, peer);
    
    let smtp_handler = nettrap_proto_smtp::SmtpHandler::new();
    let ftp_handler = nettrap_proto_ftp::FtpHandler::new();
    
    // SMTP and FTP require sending banner first
    if name == "smtp" {
        stream.write_all(smtp_handler.get_welcome_banner().as_bytes()).await?;
        stream.flush().await?;
    } else if name == "ftp" {
        stream.write_all(ftp_handler.get_banner()).await?;
        stream.flush().await?;
    }
    
    let mut buf = vec![0u8; 4096];
    
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                tracing::debug!("TCP connection closed by {}", peer);
                return Ok(());
            }
            Ok(len) => {
                tracing::debug!("TCP listener '{}' received {} bytes from {}", name, len, peer);
                
                let data = &buf[..len];
                let first_bytes = &data[..len.min(20)];
                
                let response = if name == "smtp" {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    tracing::debug!("SMTP command from {}: {}", peer, command);
                    let result = smtp_handler.handle(command).await;
                    match result {
                        Ok(resp) => format!("{} {}\r\n", resp.code, resp.message).into_bytes(),
                        Err(_) => b"500 Error\r\n".to_vec(),
                    }
                } else if name == "ftp" {
                    let command = std::str::from_utf8(data).unwrap_or("").trim();
                    tracing::debug!("FTP command from {}: {}", peer, command);
                    let resp = ftp_handler.handle(command);
                    resp.to_bytes()
                } else {
                    // Auto-detect for HTTP/TLS
                    let is_tls = first_bytes.starts_with(&[22, 3, 1]) || first_bytes.starts_with(&[22, 3, 3]);
                    let is_http = first_bytes.windows(4).any(|w| w == b"GET " || w == b"POST" || w == b"HEAD" || w == b"PUT ");
                    
                    if is_http {
                        tracing::debug!("Detected HTTP protocol from {}", peer);
                        build_http_response()
                    } else if is_tls {
                        tracing::debug!("Detected TLS protocol from {}", peer);
                        build_tls_response()
                    } else {
                        tracing::debug!("Unknown protocol from {}, sending generic response", peer);
                        b"OK\n".to_vec()
                    }
                };
                
                stream.write_all(&response).await?;
                stream.flush().await?;
            }
            Err(e) => {
                tracing::debug!("TCP read error from {}: {}", peer, e);
                return Ok(());
            }
        }
    }
}

fn build_http_response() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello NetTrap\n".to_vec()
}

fn build_tls_response() -> Vec<u8> {
    let mut response = vec![22, 3, 3, 0, 2, 0, 0];
    response.push(0x01);
    response.push(0x00);
    response.extend_from_slice(&[22, 3, 3, 0, 2, 0, 0]);
    response
}