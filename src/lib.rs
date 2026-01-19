use std::{net::IpAddr};
use chrono::prelude::*;
use regex::Regex;

#[derive(PartialEq)]
pub enum LogLevel {
  Info,
  Warning,
  Error,
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

pub enum LogMethod {
  Get,
  Post,
  Patch,
  Put,
  Delete,
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
pub struct LogEntry {
  timestamp: String,
  level: LogLevel,
  ip_address: IpAddr,
  method: LogMethod,
  endpoint: String,
  status_code: u16,
  response_time: String,
  message: Option<String>,
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
    self.entries.iter().filter(|&e| e.level.as_str() == log_level.as_str())
  }

  pub fn filter_by_date_range(&self, start: NaiveDateTime, end: NaiveDateTime) -> impl Iterator<Item = &LogEntry> {
    self.entries.iter().filter(move |&e| {
      let dt = NaiveDateTime::parse_from_str(&e.timestamp, "%Y-%m-%d %H:%M:%S%.3f").unwrap();
      dt.ge(&start) && dt.le(&end)
    })
  }

  pub fn filter_by_endpoint(&self, pattern: &str) -> impl Iterator<Item = &LogEntry> {
    let endpoint_pattern = format!(r"\b{}\b", pattern);
    self.entries.iter().filter(move |&e| {
      let regex = Regex::new( &endpoint_pattern).unwrap();
      regex.is_match(&e.endpoint)
    })
  }
}