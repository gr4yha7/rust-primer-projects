use anyhow::Context;
use chrono::{NaiveDate, NaiveDateTime};
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    collections::HashMap, fmt::{self, Display, Formatter}, fs::File, io::{BufRead, BufReader}, net::IpAddr, path::PathBuf, str::FromStr
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
  static ref DATE_EXTRACT_PATTERN: Regex = Regex::new(r"(\d{4}-\d{2}-\d{2})").unwrap();
}

#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse log entry at line {line_number}: {message}")]
    ParseError { line_number: usize, message: String },

    #[error("Invalid date format: {0}")]
    DateParseError(#[from] chrono::ParseError),

    #[error("Invalid regex pattern: {0}")]
    RegexError(#[from] regex::Error),

    #[error("Invalid HTTP method: {0}")]
    LogMethodParseError(String),

    #[error("Invalid log level: {0}")]
    LogLevelParseError(String),

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
            _ => Err(AnalyzerError::LogLevelParseError(s.to_string())),
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

impl FromStr for LogMethod {
    type Err = AnalyzerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "GET" => Ok(LogMethod::Get),
            "POST" => Ok(LogMethod::Post),
            "PATCH" => Ok(LogMethod::Patch),
            "PUT" => Ok(LogMethod::Put),
            "DELETE" => Ok(LogMethod::Delete),
            _ => Err(AnalyzerError::LogMethodParseError(s.to_string())),
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

impl Display for ParseWarning {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Warning: Could not parse line {}: {} - {}",
            self.line_number, self.error, self.line_content
        )
    }
}
#[derive(Debug, Clone)]
pub struct ParseWarning {
    pub line_number: usize,
    pub line_content: String,
    pub error: String,
}

#[derive(Debug)]
pub struct ParseResult {
    pub warnings: Vec<ParseWarning>,
    pub entries_parsed: usize,
}

impl ParseResult {
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }
}

#[derive(Debug, Clone, Default)]
pub struct LogEntry {
    pub timestamp: Option<String>,
    pub level: Option<LogLevel>,
    pub ip_address: Option<IpAddr>,
    pub method: Option<LogMethod>,
    pub endpoint: Option<String>,
    pub status_code: Option<u16>,
    pub response_time: Option<f64>,
    pub message: Option<String>,
}

impl LogEntry {
    pub fn parse_log(log_line: &str) -> Result<Self, AnalyzerError> {
        Ok(Self {
            timestamp: TIMESTAMP_PATTERN
                .find(log_line)
                .map(|m| m.as_str().to_string()),
            // .map(|m| m.parse::<NaiveDateTime>().unwrap()),
            level: LEVEL_PATTERN.find(log_line).and_then(|m| {
                m.as_str()
                    .trim_matches(&['[', ']'][..])
                    .parse::<LogLevel>()
                    .ok()
            }),
            ip_address: IP_PATTERN
                .find(log_line)
                .and_then(|m| m.as_str().parse::<IpAddr>().ok()),
            method: METHOD_PATTERN
                .find(log_line)
                .and_then(|m| m.as_str().parse::<LogMethod>().ok()),
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

    // Extract date from timestamp for filtering
    fn extract_date(&self) -> Option<NaiveDate> {
        self.timestamp.as_ref().and_then(|ts| {
            DATE_EXTRACT_PATTERN
                .find(ts)
                .and_then(|m| NaiveDate::parse_from_str(m.as_str(), "%Y-%m-%d").ok())
        })
    }
}

#[derive(Debug)]
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

    pub fn read_and_parse_log(&mut self, file_path: PathBuf) -> Result<ParseResult, AnalyzerError> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut warnings = Vec::new();
        let initial_count = self.entries.len();
        for (line_number, line_result) in reader.lines().enumerate() {
            let line_number = line_number + 1;
            match line_result {
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue; // Skip empty lines
                    }
                    let parse_result = LogEntry::parse_log(&line);
                    match parse_result {
                        Ok(entry) => self.entries.push(entry),
                        Err(e) => {
                            warnings.push(ParseWarning {
                                line_number,
                                line_content: line,
                                error: e.to_string(),
                            });
                        }
                    }
                }
                Err(e) => {
                    warnings.push(ParseWarning {
                        line_number,
                        line_content: String::from("IO Error: failed to read line"),
                        error: e.to_string(),
                    });
                }
            }
        }
        let entries_parsed = self.entries.len() - initial_count;
        if entries_parsed == 0 {
            return Err(AnalyzerError::EmptyLogFile);
        }
        Ok(ParseResult {
            warnings,
            entries_parsed,
        })
    }

    pub fn filter_by_level(
        &self,
        log_level: &str,
    ) -> Result<impl Iterator<Item = &LogEntry>, AnalyzerError> {
        Ok(self.entries.iter().filter(|&e| {
            e.level
                .as_ref()
                .map(|level| {
                    level.to_string() == log_level.parse::<LogLevel>().unwrap().to_string()
                })
                .unwrap_or(false)
        }))
    }

    pub fn filter_by_date_range(
        &self,
        start: &str,
        end: &str,
    ) -> Result<impl Iterator<Item = &LogEntry>, AnalyzerError> {
        let start = NaiveDate::parse_from_str(start, "%Y-%m-%d")?;
        let end = NaiveDate::parse_from_str(end, "%Y-%m-%d")?;
        Ok(self.entries.iter().filter(move |&e| {
            e.extract_date()
                .as_ref()
                .map(|d| d.ge(&start) && d.le(&end))
                .unwrap_or(false)
        }))
    }

    pub fn filter_by_endpoint(
        &self,
        pattern: &str,
    ) -> Result<impl Iterator<Item = &LogEntry>, AnalyzerError> {
        let endpoint_pattern = Regex::new(&regex::escape(pattern))?;
        Ok(self.entries.iter().filter(move |&e| {
            e.endpoint
                .as_ref()
                .map(|endpoint| endpoint_pattern.is_match(endpoint))
                .unwrap_or(false)
        }))
    }
}

#[derive(Debug)]
pub struct LogStats {
    pub total_requests: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub avg_response_time: f64,
    pub endpoint_frequency: HashMap<String, usize>,
    pub errors_by_endpoint: HashMap<String, usize>,
    pub slowest_requests: Vec<LogEntry>, // top 10 slowest
}

impl LogStats {
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            error_count: 0,
            warning_count: 0,
            info_count: 0,
            avg_response_time: 0.0,
            endpoint_frequency: HashMap::new(),
            errors_by_endpoint: HashMap::new(),
            slowest_requests: Vec::new(),
        }
    }

    pub fn from_entries(entries: &[LogEntry]) -> Self {
        let total_requests = entries.len();
        let mut error_count: usize = 0;
        let mut warning_count: usize = 0;
        let mut info_count: usize = 0;
        let mut avg_response_time = 0.0;
        let mut sum_response_time = 0.0;
        let mut requests = Vec::with_capacity(entries.len());
        requests.resize(entries.len(), LogEntry::default());
        println!("entries len = {}, reqs len = {}", entries.len(), requests.len());
        requests.clone_from_slice(entries);
        let mut endpoint_frequency = HashMap::new();
        let mut errors_by_endpoint = HashMap::new();
        for entry in entries {
            if let Some(level) = &entry.level {
                match level {
                    LogLevel::Info =>info_count += 1,
                    LogLevel::Warning => warning_count += 1,
                    LogLevel::Error => {
                        error_count += 1;
                        if let Some(endpoint) = &entry.endpoint {
                            errors_by_endpoint.entry(endpoint.clone()).and_modify(|count| *count += 1).or_insert(1);
                        }
                    }
                }
            }
            if let Some(endpoint) = &entry.endpoint {
                endpoint_frequency.entry(endpoint.clone()).and_modify(|count| *count += 1).or_insert(1);
            }
            if let Some(response_time) = entry.response_time {
                sum_response_time += response_time;
            }
        }
        avg_response_time = sum_response_time / total_requests as f64;
        requests.sort_by(|a, b| b.response_time.partial_cmp(&a.response_time).unwrap_or(std::cmp::Ordering::Equal));
        let slowest_requests = requests.to_vec();

        Self {
            total_requests,
            info_count,
            warning_count,
            error_count,
            avg_response_time,
            endpoint_frequency,
            errors_by_endpoint,
            slowest_requests,
        }

    }
}
