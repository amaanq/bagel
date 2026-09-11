//! `bagel` admin CLI.

#![expect(
   clippy::missing_asserts_for_indexing,
   reason = "the indexing is inside code the pound derive generates"
)]

use std::path::PathBuf;

use anyhow::Context;
use bagel_admin::{
   Request,
   Response,
};
use pound::Parse;

#[derive(Parse)]
#[pound(name = "bagel")]
struct Cli {
   /// Path to the daemon admin socket.
   #[pound(long, short = 's', env = "BAGEL_ADMIN_SOCKET", global = true)]
   socket: Option<PathBuf>,

   /// Emit machine-readable JSON instead of formatted text.
   #[pound(long, global = true)]
   json: bool,

   #[pound(subcommand)]
   command: Command,
}

#[derive(Parse)]
enum Command {
   /// Show daemon status and counters.
   Status,
   /// Add a manual durable ban for an address or CIDR.
   Block {
      network:       String,
      #[pound(long)]
      duration_secs: Option<u64>,
   },
   /// Remove manual and automatic bans for an address or CIDR.
   Unblock { network: String },
   /// List active durable enforcement leases.
   Bans,
   /// List configured defense policies.
   Policies,
   /// Rebuild Bagel's nftables table from durable leases.
   Reconcile,
   /// Configuration tooling that runs without the daemon.
   Config {
      #[pound(subcommand)]
      action: ConfigCommand,
   },
}

#[derive(Parse)]
enum ConfigCommand {
   /// Print a starter KDL configuration covering both planes.
   Example,
}

#[expect(
   clippy::print_stderr,
   clippy::print_stdout,
   reason = "the CLI writes its results to stdout and its startup errors to stderr"
)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
   for variable in Cli::SPEC.args.iter().filter_map(|argument| argument.env) {
      if let Err(std::env::VarError::NotUnicode(_)) = std::env::var(variable) {
         eprintln!("{variable} must be valid UTF-8");
         std::process::exit(2);
      }
   }
   let arguments: Vec<String> = std::env::args_os()
      .skip(1)
      .map(|argument| {
         argument.into_string().unwrap_or_else(|_| {
            eprintln!("command-line arguments must be valid UTF-8");
            std::process::exit(2);
         })
      })
      .collect();
   let cli = Cli::parse_from(arguments.iter().map(String::as_str));

   if let Command::Config { action } = &cli.command {
      run_config(action);
      return Ok(());
   }

   let request = match &cli.command {
      Command::Status => Request::Status,
      Command::Block {
         network,
         duration_secs,
      } => {
         Request::Block {
            network:       network.clone(),
            duration_secs: *duration_secs,
         }
      },
      Command::Unblock { network } => {
         Request::Unblock {
            network: network.clone(),
         }
      },
      Command::Bans => Request::ListBans,
      Command::Policies => Request::ListPolicies,
      Command::Reconcile => Request::Reconcile,
      Command::Config { .. } => return Ok(()),
   };

   let socket = cli
      .socket
      .unwrap_or_else(|| PathBuf::from(bagel_core::DEFAULT_ADMIN_SOCKET));
   let response = bagel_admin::query(&socket, &request)
      .await
      .with_context(|| format!("cannot reach the bagel daemon at {}", socket.display()))?;

   let is_error = matches!(response, Response::Error(_));
   if cli.json {
      println!("{}", serde_json::to_string_pretty(&response)?);
      if is_error {
         std::process::exit(1);
      }
   } else if let Response::Error(msg) = &response {
      return Err(anyhow::anyhow!("{msg}"));
   } else {
      print!("{response}");
   }

   Ok(())
}

#[expect(
   clippy::print_stdout,
   reason = "printing the example config to stdout is what the subcommand is for"
)]
fn run_config(action: &ConfigCommand) {
   match action {
      ConfigCommand::Example => print!("{}", include_str!("../../../examples/bagel.kdl")),
   }
}
