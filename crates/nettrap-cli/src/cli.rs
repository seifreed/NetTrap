use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "nettrap")]
#[command(author = "NetTrap Team")]
#[command(version = "0.1.0")]
#[command(about = "Network Interception, Emulation & Deception Engine")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[arg(short = 'c', long, global = true)]
    pub config: Option<std::path::PathBuf>,

    /// Log to file
    #[arg(short = 'l', long, global = true)]
    pub log_file: Option<std::path::PathBuf>,

    /// Log to syslog
    #[arg(short = 's', long, global = true)]
    pub log_syslog: bool,

    /// Stop flag file - graceful shutdown when this file is created
    #[arg(short = 'f', long, global = true)]
    pub stop_flag: Option<std::path::PathBuf>,

    /// Suppress console output
    #[arg(short = 'n', long, global = true)]
    pub no_console: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Run(RunArgs),
    Config(ConfigArgs),
    Pcap(PcapArgs),
    Report(ReportArgs),
    Status(StatusArgs),
    Test(TestArgs),
    /// Launch interactive TUI dashboard
    Tui(TuiArgs),
    /// Start REST API server
    Api(ApiArgs),
    /// TLS certificate management (mkcert integration)
    Tls(TlsArgs),
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    #[arg(short = 'i', long)]
    pub interface: Option<String>,

    #[arg(short = 'p', long)]
    pub ports: Vec<u16>,

    #[arg(short = 'a', long)]
    pub attribution: bool,

    #[arg(short = 'I', long)]
    pub intercept: bool,

    #[arg(short, long)]
    pub emulate: bool,

    #[arg(short = 'o', long)]
    pub output: Option<std::path::PathBuf>,

    #[arg(long)]
    pub pcap: bool,

    #[arg(long)]
    pub pcap_path: Option<std::path::PathBuf>,

    #[arg(long)]
    pub verbose_flows: bool,

    #[arg(long)]
    pub log_level: Option<String>,

    #[arg(long)]
    pub json_output: bool,

    /// Output format for reports: json, jsonl, sarif, toon, csv (default: jsonl)
    #[arg(long = "report-format")]
    pub report_format: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ConfigArgs {
    #[arg(short = 'o', long)]
    pub output: Option<std::path::PathBuf>,

    #[arg(short, long)]
    pub check: bool,

    #[arg(short, long)]
    pub defaults: bool,
}

#[derive(Parser, Debug)]
pub struct PcapArgs {
    #[arg(short = 'i', long)]
    pub input: std::path::PathBuf,

    #[arg(short = 'o', long)]
    pub output: Option<std::path::PathBuf>,

    #[arg(short, long)]
    pub live: bool,
}

#[derive(Parser, Debug)]
pub struct ReportArgs {
    #[arg(short = 'i', long)]
    pub input: std::path::PathBuf,

    #[arg(short = 'o', long)]
    pub output: Option<std::path::PathBuf>,

    #[arg(short = 'f', long)]
    pub format: Option<String>,
}

#[derive(Parser, Debug)]
pub struct StatusArgs {
    #[arg(short, long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct TestArgs {
    #[arg(short = 'f', long)]
    pub file: Option<std::path::PathBuf>,

    #[arg(short, long)]
    pub unit: bool,

    #[arg(short, long)]
    pub integration: bool,
}

#[derive(Parser, Debug)]
pub struct TuiArgs {
    /// NBI JSONL file to display
    #[arg(short = 'i', long)]
    pub input: Option<std::path::PathBuf>,
}

#[derive(Parser, Debug)]
pub struct ApiArgs {
    /// API bind address
    #[arg(short, long, default_value = "127.0.0.1:9090")]
    pub bind: String,
}

#[derive(Parser, Debug)]
pub struct TlsArgs {
    #[command(subcommand)]
    pub command: TlsCommands,
}

#[derive(Subcommand, Debug)]
pub enum TlsCommands {
    /// Show TLS/mkcert status
    Status,
    /// Install mkcert binary from GitHub
    InstallMkcert,
    /// Install mkcert CA into system trust stores (requires mkcert)
    Install,
    /// Generate a certificate for specific hostnames
    Generate(TlsGenerateArgs),
    /// Show the CA root directory
    Caroot,
}

#[derive(Parser, Debug)]
pub struct TlsGenerateArgs {
    /// Hostnames to generate certificate for
    #[arg(required = true)]
    pub hostnames: Vec<String>,

    /// Output directory for cert/key files
    #[arg(short = 'o', long, default_value = ".")]
    pub output_dir: PathBuf,
}
