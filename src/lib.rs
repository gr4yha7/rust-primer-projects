use std::{
  fs::File,
  io::{BufReader, BufRead},
  net::IpAddr,
  str::FromStr,
};
use chrono::prelude::*;
use regex::Regex;
use thiserror::Error;

#[derive(Error, Debug)]
enum AnalyzerError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Failed to parse log entry on line {line}: {message}")]
    ParseError { line: usize, message: String },
    
    #[error("Invalid date format: {0}")]
    DateParseError(String),
    
    #[error("No log entries found in file")]
    EmptyLogFile,
}

#[derive(Debug, PartialEq, Clone)]
pub enum LogLevel {
  Info,
  Warning,
  Error,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LogLevelParseError(String);

impl FromStr for LogLevel {
    type Err = LogLevelParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
      match s {
          "INFO" => Ok(LogLevel::Info),
          "WARNING" => Ok(LogLevel::Warning),
          "ERROR" => Ok(LogLevel::Error),
          _ => Err(LogLevelParseError(String::from("invalid log level"))),
      }
    }
}
impl LogLevel {
  pub fn as_str(&self) -> &str {
    match self {
      LogLevel::Info => "INFO",
      LogLevel::Warning => "WARNING",
      LogLevel::Error => "ERROR",
    }
  }
}

#[derive(Debug, Clone)]
pub enum LogMethod {
  Get,
  Post,
  Patch,
  Put,
  Delete,
}
#[derive(Debug, PartialEq, Eq)]
pub struct LogMethodParseError(String);

impl FromStr for LogMethod {
    type Err = LogMethodParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
      match s {
          "GET" => Ok(LogMethod::Get),
          "POST" => Ok(LogMethod::Post),
          "PATCH" => Ok(LogMethod::Patch),
          "PUT" => Ok(LogMethod::Put),
          "DELETE" => Ok(LogMethod::Delete),
          _ => Err(LogMethodParseError(String::from("invalid log method"))),
      }
    }
}
impl LogMethod {
  pub fn as_str(&self) -> &str {
    match self {
      LogMethod::Get => "GET",
      LogMethod::Post => "POST",
      LogMethod::Patch => "PATCH",
      LogMethod::Put => "PUT",
      LogMethod::Delete => "DELETE",
    }
  }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
  timestamp: Option<String>,
  level: Option<LogLevel>,
  ip_address: Option<IpAddr>,
  method: Option<LogMethod>,
  endpoint: Option<String>,
  status_code: Option<u16>,
  response_time: Option<f64>,
  message: Option<String>,
}

impl LogEntry {
  pub fn parse_log(log_line: &str) -> Self {
    let timestamp_pattern = Regex::new(
        r"(?:\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\])|(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?Z?)"
    ).unwrap();
    
    let level_pattern = Regex::new(r"(?:DEBUG|INFO|WARNING|ERROR|FATAL)").unwrap();
    let ip_pattern = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    let method_pattern = Regex::new(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b").unwrap();
    let endpoint_pattern = Regex::new(r#"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^\s"]+)"#).unwrap();
    let status_pattern = Regex::new(r"\s+(\d{3})\s+").unwrap();
    let response_time_pattern = Regex::new(r"(\d+(?:\.\d+)?)\s*(?:ms|s)").unwrap();
    let message_pattern = Regex::new(r"\d+(?:\.\d+)?\s*(?:ms|s)\s+(.+)$").unwrap();
    
    Self {
        timestamp: timestamp_pattern.find(log_line)
            .map(|m| m.as_str().to_string()),
            // .map(|m| m.parse::<NaiveDateTime>().unwrap()),
        level: level_pattern.find(log_line)
            .map(|m| m.as_str().parse::<LogLevel>().unwrap()),
        ip_address: ip_pattern.find(log_line)
            .map(|m| m.as_str().parse::<IpAddr>().unwrap()),
        method: method_pattern.find(log_line)
            .map(|m| m.as_str().parse::<LogMethod>().unwrap()),
        endpoint: endpoint_pattern.captures(log_line)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string())),
        status_code: status_pattern.captures(log_line)
            .and_then(|c| c.get(1).map(|m| m.as_str().parse::<u16>().ok()))
            .flatten(),
        response_time: response_time_pattern.captures(log_line)
            .and_then(|c| c.get(1).map(|m| m.as_str().parse().ok()))
            .flatten(),
        message: message_pattern.captures(log_line)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string())),
    }
  }

  fn read_and_parse_log(file_path: &str) -> Result<Vec<LogEntry>, AnalyzerError> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
      let entry = Self::parse_log(&line?);
      entries.push(entry);
    }
    Ok(entries)
  }
}

pub struct Logs {
  pub entries: Vec<LogEntry>
}
impl Default for Logs {
  fn default() -> Self {
      Self::new()
  }
}
impl Logs {
  fn new() -> Self {
    Self { entries: Vec::new() }
  }

  pub fn filter_by_level(&self, log_level: &LogLevel) -> impl Iterator<Item = &LogEntry> {
    self.entries.iter().filter(|&e| {
      if let Some(level) = e.level.as_ref() {
        level.as_str() == log_level.as_str()
      } else { false }
    })
  }

  pub fn filter_by_date_range(&self, start: NaiveDateTime, end: NaiveDateTime) -> impl Iterator<Item = &LogEntry> {
    self.entries.iter().filter(move |&e| {
      if let Some(timestamp) = e.timestamp.as_ref() {
        let dt = NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S%.3f").unwrap();
        dt.ge(&start) && dt.le(&end)
      } else {
        false
      }
    })
  }

  pub fn filter_by_endpoint(&self, pattern: &str) -> impl Iterator<Item = &LogEntry> {
    let endpoint_pattern = format!(r"\b{}\b", pattern);
    self.entries.iter().filter(move |&e| {
      if let Some(endpoint) = e.endpoint.as_ref() {
        let regex = Regex::new( &endpoint_pattern).unwrap();
        regex.is_match(endpoint)
      } else {
        false
      }
    })
  }

}
