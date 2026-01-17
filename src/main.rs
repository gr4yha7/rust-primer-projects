use std::{
    fs::File,
    io::{BufRead, BufReader, Result},
};
use clap::Parser;
use serde::{Serialize, Deserialize};

#[derive(Parser)]
#[command(name="Loggaliza", version, about("Server logs file analyzer"), long_about = None)]
struct Opts {
    #[arg(short = 'i', long)]
    input_file: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum ApiError {
    DetailedError {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "statusCode")]
        status_code: Option<u16>,
    },
    SimpleError {
        code: String,
    },
    SimpleErrorString(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct LogEntry {
    error: ApiError,
    level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
}

fn main() -> Result<()> {
    let args = Opts::parse();
    // let file_path: PathBuf = PathBuf::from(args.input_file);
    let file = File::open(args.input_file)?; 
    let reader = BufReader::new(file);

    for line in reader.lines() {
        // println!("read line: {:?}", line);
        let entry = line.unwrap();
        let log_entry: LogEntry = serde_json::from_str(&entry)?;
        println!("log entry: {:?}", log_entry);
    }

    Ok(())

    // println!("input file path: {:?}", args.input_file);
}
