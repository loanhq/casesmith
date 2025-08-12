use casesmith::{handle_run, handle_generate};
use clap::{Parser};
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum Cli {
    /// Run the default command
    Run {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        verbose: bool,
        #[arg(short, long, default_value_t = 1)]
        count: u8,
    },
    /// Generate something (example command)
    Generate {
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    // Always read config.toml and pass to handlers
    let config_path = Path::new("config.toml");
    let config = match fs::read_to_string(config_path) {
        Ok(contents) => contents,
        Err(e) => {
            eprintln!("Warning: Could not read config.toml: {}", e);
            String::new()
        }
    };

    match cli {
        Cli::Run { name, verbose, count } => {
            handle_run(name, verbose, count, &config);
        }
        Cli::Generate { output } => {
            handle_generate(output, &config);
        }
    }
}

// handlers are now in lib.rs
