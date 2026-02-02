use anyhow::Context;
use chrono::{NaiveDate, NaiveDateTime};
use colored::*;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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
        let mut sum_response_time: f64 = 0.0;
        let mut requests = Vec::with_capacity(total_requests);
        requests.resize(total_requests, LogEntry::default());
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
        let avg_response_time = sum_response_time / total_requests as f64;
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

    /// Print a comprehensive formatted report to stdout
    pub fn print_report(&self) {
        self.print_header();
        self.print_summary();
        self.print_performance();
        self.print_top_endpoints();
        self.print_error_analysis();
        self.print_slowest_requests();
        self.print_footer();
    }

    /// Export stats to JSON format
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    fn print_header(&self) {
        println!("\n{}", "╔═══════════════════════════════════════════════════════════════╗".bright_cyan());
        println!("{}", "║          LOG ANALYSIS REPORT                                  ║".bright_cyan().bold());
        println!("{}", "╚═══════════════════════════════════════════════════════════════╝".bright_cyan());
    }

    fn print_footer(&self) {
        println!("{}", "═".repeat(65).bright_cyan());
        println!();
    }

    fn print_summary(&self) {
        println!("\n{}", "📊 SUMMARY STATISTICS".bold().bright_white());
        println!("{}", "─".repeat(65).bright_black());
        
        println!("{:<30} {:>10}", "Total Requests:", format!("{}", self.total_requests).bright_white().bold());
        
        // Status breakdown with percentages and color coding
        let info_pct = (self.info_count as f64 / self.total_requests as f64) * 100.0;
        let warning_pct = (self.warning_count as f64 / self.total_requests as f64) * 100.0;
        let error_pct = (self.error_count as f64 / self.total_requests as f64) * 100.0;
        
        println!("\n{}", "Status Breakdown:".bright_white());
        println!("  {:<26} {:>8}  {:>6}", 
            "INFO".green(), 
            format!("{}", self.info_count).green(),
            format!("({:.1}%)", info_pct).bright_black()
        );
        println!("  {:<26} {:>8}  {:>6}", 
            "WARNING".yellow(), 
            format!("{}", self.warning_count).yellow(),
            format!("({:.1}%)", warning_pct).bright_black()
        );
        println!("  {:<26} {:>8}  {:>6}", 
            "ERROR".red(), 
            format!("{}", self.error_count).red().bold(),
            format!("({:.1}%)", error_pct).bright_black()
        );
        
        // Error rate indicator
        if error_pct > 5.0 {
            println!("\n  {} {}", "⚠".yellow(), format!("High error rate detected: {:.1}%", error_pct).yellow().bold());
        } else if error_pct > 1.0 {
            println!("\n  {} {}", "ℹ".bright_blue(), format!("Moderate error rate: {:.1}%", error_pct).bright_blue());
        }
    }

    fn print_performance(&self) {
        println!("\n{}", "⚡ PERFORMANCE METRICS".bold().bright_white());
        println!("{}", "─".repeat(65).bright_black());
        
        println!("{:<30} {:>10}", 
            "Average Response Time:", 
            format!("{:.2}ms", self.avg_response_time).bright_cyan()
        );
        
        // Calculate percentiles if we have response times
        let mut response_times: Vec<f64> = self.slowest_requests
            .iter()
            .filter_map(|e| e.response_time)
            .collect();
        
        if !response_times.is_empty() {
            response_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            
            let p50_idx = (response_times.len() as f64 * 0.50) as usize;
            let p95_idx = (response_times.len() as f64 * 0.95) as usize;
            let p99_idx = (response_times.len() as f64 * 0.99) as usize;
            
            if p50_idx < response_times.len() {
                println!("{:<30} {:>10}", 
                    "P50 Response Time:", 
                    format!("{:.2}ms", response_times[p50_idx]).bright_green()
                );
            }
            if p95_idx < response_times.len() {
                println!("{:<30} {:>10}", 
                    "P95 Response Time:", 
                    format!("{:.2}ms", response_times[p95_idx]).yellow()
                );
            }
            if p99_idx < response_times.len() {
                println!("{:<30} {:>10}", 
                    "P99 Response Time:", 
                    format!("{:.2}ms", response_times[p99_idx]).red()
                );
            }
        }
    }

    fn print_top_endpoints(&self) {
        println!("\n{}", "🔝 TOP 10 ENDPOINTS BY REQUEST COUNT".bold().bright_white());
        println!("{}", "─".repeat(65).bright_black());
        
        let mut endpoints: Vec<_> = self.endpoint_frequency.iter().collect();
        endpoints.sort_by(|a, b| b.1.cmp(a.1));
        
        println!("{:<4} {:<40} {:>10}", 
            "#".bright_black(), 
            "Endpoint".bright_black(), 
            "Count".bright_black()
        );
        println!("{}", "─".repeat(65).bright_black());
        
        for (i, (endpoint, count)) in endpoints.into_iter().take(10).enumerate() {
            let bar_width = (*count as f64 / self.total_requests as f64 * 30.0) as usize;
            let bar = "█".repeat(bar_width);
            
            println!("{:<4} {:<40} {:>10} {}", 
                format!("{}", i + 1).bright_cyan(),
                Self::truncate_endpoint(endpoint, 40),
                format!("{}", count).bright_white().bold(),
                bar.bright_blue()
            );
        }
    }

    fn print_error_analysis(&self) {
        if self.errors_by_endpoint.is_empty() {
            println!("\n{}", "✅ ERROR ANALYSIS: No errors detected".bold().green());
            return;
        }
        
        println!("\n{}", "🚨 ERROR ANALYSIS".bold().bright_white());
        println!("{}", "─".repeat(65).bright_black());
        
        let mut errors: Vec<_> = self.errors_by_endpoint.iter().collect();
        errors.sort_by(|a, b| b.1.cmp(a.1));
        
        println!("{:<4} {:<40} {:>10}", 
            "#".bright_black(), 
            "Endpoint".bright_black(), 
            "Errors".bright_black()
        );
        println!("{}", "─".repeat(65).bright_black());
        
        for (i, (endpoint, count)) in errors.iter().take(10).enumerate() {
            println!("{:<4} {:<40} {:>10}", 
                format!("{}", i + 1).bright_cyan(),
                Self::truncate_endpoint(endpoint, 40),
                format!("{}", count).red().bold()
            );
        }
    }

    fn print_slowest_requests(&self) {
        println!("\n{}", "🐌 TOP 10 SLOWEST REQUESTS".bold().bright_white());
        println!("{}", "─".repeat(65).bright_black());
        
        println!("{:<4} {:<35} {:<10} {:>10}", 
            "#".bright_black(), 
            "Endpoint".bright_black(),
            "Method".bright_black(),
            "Time".bright_black()
        );
        println!("{}", "─".repeat(65).bright_black());
        
        for (i, entry) in self.slowest_requests.iter().take(10).enumerate() {
            if let Some(response_time) = entry.response_time {
                let endpoint = entry.endpoint.as_deref().unwrap_or("N/A");
                let method = entry.method.as_ref().map(|m| m.to_string()).unwrap_or_else(|| "N/A".to_string());
                
                let time_color = if response_time > 1000.0 {
                    format!("{:.2}ms", response_time).red().bold()
                } else if response_time > 500.0 {
                    format!("{:.2}ms", response_time).yellow()
                } else {
                    format!("{:.2}ms", response_time).bright_white()
                };
                
                println!("{:<4} {:<35} {:<10} {:>10}", 
                    format!("{}", i + 1).bright_cyan(),
                    Self::truncate_endpoint(endpoint, 35),
                    method,
                    time_color
                );
            }
        }
    }

    fn truncate_endpoint(endpoint: &str, max_len: usize) -> String {
        if endpoint.len() > max_len {
            format!("{}...", &endpoint[..max_len - 3])
        } else {
            endpoint.to_string()
        }
    }
}

impl Display for LogStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Log Analysis Report ===")?;
        writeln!(f, "Total Requests: {}", self.total_requests)?;
        writeln!(f, "\nStatus Breakdown:")?;
        writeln!(f, "  INFO:    {} ({:.1}%)", 
            self.info_count, 
            (self.info_count as f64 / self.total_requests as f64) * 100.0
        )?;
        writeln!(f, "  WARNING: {} ({:.1}%)", 
            self.warning_count, 
            (self.warning_count as f64 / self.total_requests as f64) * 100.0
        )?;
        writeln!(f, "  ERROR:   {} ({:.1}%)", 
            self.error_count, 
            (self.error_count as f64 / self.total_requests as f64) * 100.0
        )?;
        writeln!(f, "\nPerformance:")?;
        writeln!(f, "  Avg Response Time: {:.2}ms", self.avg_response_time)?;
        
        Ok(())
    }
}