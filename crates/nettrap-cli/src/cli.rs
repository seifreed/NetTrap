use clap::{Parser, Subcommand};

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
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Run(RunArgs),
    Config(ConfigArgs),
    Pcap(PcapArgs),
    Report(ReportArgs),
    Status(StatusArgs),
    Test(TestArgs),
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
