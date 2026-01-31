#![allow(unused)]
use std::{
    fs::File,
    io::{BufRead, BufReader}, path::PathBuf,
};
use clap::Parser;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use loggaliza::log_analyzer::{AnalyzerError, LogEntry, Logs};

#[derive(Parser)]
#[command(name="Loggaliza", version, about("Server logs file analyzer"), long_about = None)]
struct Opts {
    #[arg(short = 'i', long)]
    input_file: PathBuf,
}

// #[derive(Debug, Serialize, Deserialize)]
// #[serde(untagged)]
// enum ApiError {
//     DetailedError {
//         code: String,
//         #[serde(skip_serializing_if = "Option::is_none")]
//         name: Option<String>,
//         #[serde(skip_serializing_if = "Option::is_none")]
//         #[serde(rename = "statusCode")]
//         status_code: Option<u16>,
//     },
//     SimpleError {
//         code: String,
//     },
//     SimpleErrorString(String),
// }

// #[derive(Debug, Serialize, Deserialize)]
// struct LogEntry {
//     error: ApiError,
//     level: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     method: Option<String>,
//     message: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     path: Option<String>,
//     service: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     timestamp: Option<String>,
// }

fn main() -> Result<(), AnalyzerError> {
    let args = Opts::parse();

    let file_exists = args.input_file.try_exists()?;
    if !file_exists {
        panic!("File does not exist")
    }
    let mut logs: Logs = Logs::default();
    logs.read_and_parse_log(args.input_file)?;

    // let logs_by_level: Vec<&LogEntry> = logs.filter_by_level("INFO")?.collect();
    // let logs_by_endpoint: Vec<&LogEntry> = logs.filter_by_endpoint("api/products")?.collect();
    let logs_by_date_range: Vec<&LogEntry> = logs.filter_by_date_range("2024-01-16", "2024-01-18")?.collect();
    // print!("logs by level: {:?}", logs_by_level);
    print!("logs by date_range: {:?}", logs_by_date_range);
    Ok(())
}
