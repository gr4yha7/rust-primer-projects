use chrono::{NaiveDate, NaiveDateTime};
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    fmt::{self, Display, Formatter},
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
};
use thiserror::Error;

lazy_static! {
  static ref TIMESTAMP_PATTERN: Regex = Regex::new(
      r"(?:\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\])|(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?Z?)"
  ).unwrap();

  static ref LEVEL_PATTERN: Regex = Regex::new(r"(?:DEBUG|INFO|WARNING|ERROR|FATAL)").unwrap();
  static ref IP_PATTERN: Regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
  static ref METHOD_PATTERN: Regex = Regex::new(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b").unwrap();
  static ref ENDPOINT_PATTERN: Regex = Regex::new(r#"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^\s"]+)"#).unwrap();
  static ref STATUS_PATTERN: Regex = Regex::new(r"\s+(\d{3})\s+").unwrap();
  static ref RESPONSE_TIME_PATTERN: Regex = Regex::new(r"(\d+(?:\.\d+)?)\s*(?:ms|s)").unwrap();
  static ref MESSAGE_PATTERN: Regex = Regex::new(r"\d+(?:\.\d+)?\s*(?:ms|s)\s+(.+)$").unwrap();
}

#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse log entry '{line}': {source}")]
    ParseError {
        line: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("Invalid date format: {0}")]
    DateParseError(#[from] chrono::ParseError),

    #[error("Invalid regex: {0}")]
    RegexError(#[from] regex::Error),

    #[error("No log entries found in file")]
    EmptyLogFile,
}

#[derive(Debug, PartialEq, Clone)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let level = match self {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARNING",
            LogLevel::Error => "ERROR",
        };
        write!(f, "{level}")
    }
}

impl FromStr for LogLevel {
    type Err = AnalyzerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "INFO" => Ok(LogLevel::Info),
            "WARNING" => Ok(LogLevel::Warning),
            "ERROR" => Ok(LogLevel::Error),
            _ => Err(AnalyzerError::ParseError {
                line: s.to_string(),
                source: anyhow::anyhow!("Invalid log level"),
            }),
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

impl Display for LogMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let method = match self {
            LogMethod::Get => "GET",
            LogMethod::Post => "POST",
            LogMethod::Patch => "PATCH",
            LogMethod::Put => "PUT",
            LogMethod::Delete => "DELETE",
        };
        write!(f, "{method}")
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
    pub fn parse_log(log_line: &str) -> Result<Self, AnalyzerError> {
        Ok(Self {
            timestamp: TIMESTAMP_PATTERN
                .find(log_line)
                .map(|m| m.as_str().to_string()),
            // .map(|m| m.parse::<NaiveDateTime>().unwrap()),
            level: LEVEL_PATTERN
                .find(log_line)
                .map(|m| m.as_str().parse::<LogLevel>().unwrap()),
            ip_address: IP_PATTERN
                .find(log_line)
                .map(|m| m.as_str().parse::<IpAddr>().unwrap()),
            method: METHOD_PATTERN
                .find(log_line)
                .map(|m| m.as_str().parse::<LogMethod>().unwrap()),
            endpoint: ENDPOINT_PATTERN
                .captures(log_line)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string())),
            status_code: STATUS_PATTERN
                .captures(log_line)
                .and_then(|c| c.get(1).map(|m| m.as_str().parse::<u16>().ok()))
                .flatten(),
            response_time: RESPONSE_TIME_PATTERN
                .captures(log_line)
                .and_then(|c| c.get(1).map(|m| m.as_str().parse().ok()))
                .flatten(),
            message: MESSAGE_PATTERN
                .captures(log_line)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string())),
        })
    }
}

pub struct Logs {
    pub entries: Vec<LogEntry>,
}
impl Default for Logs {
    fn default() -> Self {
        Self::new()
    }
}
impl Logs {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn read_and_parse_log(&mut self, file_path: PathBuf) -> Result<(), AnalyzerError> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let entry = LogEntry::parse_log(&line?)?;
            self.entries.push(entry);
        }
        Ok(())
    }

    pub fn filter_by_level(
        &self,
        log_level: &str,
    ) -> Result<impl Iterator<Item = &LogEntry>, AnalyzerError> {
        Ok(self.entries.iter().filter(|&e| {
            if let Some(level) = e.level.as_ref() {
                level.to_string() == log_level.parse::<LogLevel>().unwrap().to_string()
            } else {
                false
            }
        }))
    }

    pub fn filter_by_date_range(
        &self,
        start: &str,
        end: &str,
    ) -> Result<impl Iterator<Item = &LogEntry>, AnalyzerError> {
        let start = NaiveDateTime::parse_from_str(start, "%Y-%m-%d")?;
        let end = NaiveDateTime::parse_from_str(end, "%Y-%m-%d")?;
        Ok(self.entries.iter().filter(move |&e| {
            if let Some(timestamp) = e.timestamp.as_ref() {
                let parsed_timestamp =
                    NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S%.3f");
                match parsed_timestamp {
                    Ok(dt) => dt.ge(&start) && dt.le(&end),
                    Err(_) => false,
                }
            } else {
                false
            }
        }))
    }

    pub fn filter_by_endpoint(
        &self,
        pattern: &str,
    ) -> Result<impl Iterator<Item = &LogEntry>, AnalyzerError> {
        let endpoint_pattern =
            Regex::new(&format!(r"\b{}\b", regex::escape(pattern)))?;
        Ok(self.entries.iter().filter(move |&e| {
            e.endpoint
                .as_ref()
                .map(|endpoint| endpoint_pattern.is_match(endpoint))
                .unwrap_or(false)
        }))
    }
}
