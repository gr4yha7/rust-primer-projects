#![allow(unused)]
use std::{
    fs::File,
    io::{BufRead, BufReader}, path::PathBuf,
};
use clap::Parser;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use loggaliza::log_analyzer::{AnalyzerError, LogEntry, LogStats, Logs};

#[derive(Parser)]
#[command(name="Loggaliza", version, about("Server logs file analyzer"), long_about = None)]
struct Opts {
    #[arg(short = 'i', long)]
    input_file: PathBuf,
}

fn main() -> Result<(), AnalyzerError> {
    let args = Opts::parse();

    let file_exists = args.input_file.try_exists()?;
    if !file_exists {
        panic!("File does not exist")
    }
    let mut logs: Logs = Logs::default();
    logs.read_and_parse_log(args.input_file)?;
    let stats = LogStats::from_entries(&logs.entries);
    stats.print_report();
    Ok(())
}
