// File: sshtether/src/config.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-11-18 14:35:08 SE Asia Standard Time
// Description:
// License: MIT

//! Server configuration: file loading (TOML or JSON), validation and path
//! expansion.
//!
//! ```toml
//! [[server]]
//! name     = "Server 1"
//! hostname = "203.0.113.5"
//! username = "root"
//! port     = 22
//! key_file = "~/.ssh/id_ed25519"      # or key_files = ["a", "b"]
//! ```

use crate::cli::Cli;
use crate::error::ConfigError;
use crate::ui;
use serde::Deserialize;
use serde_json::Value;
use std::fmt;
use std::path::{Path, PathBuf};

/// One server to connect to.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Display name.
    pub name: String,
    /// Host name or IP address.
    pub hostname: String,
    /// Login name.
    pub username: String,
    /// TCP port.
    pub port: u16,
    /// Private keys to try, in order (already expanded).
    pub key_files: Vec<PathBuf>,
    /// Optional password (config file or `SSHTETHER_PASSWORD`).
    pub password: Option<String>,
}

impl ServerConfig {
    /// `name (user@host:port)`.
    pub fn label(&self) -> String {
        format!(
            "{} ({}@{}:{})",
            self.name, self.username, self.hostname, self.port
        )
    }
}

// Hand-written so the password can never leak through `{:?}`.
impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("name", &self.name)
            .field("hostname", &self.hostname)
            .field("username", &self.username)
            .field("port", &self.port)
            .field("key_files", &self.key_files)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PortValue {
    Num(i64),
    Text(String),
}

/// Unknown keys are rejected so a typo such as `usernme` cannot silently fall
/// back to a default.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawServer {
    name: Option<String>,
    #[serde(alias = "host")]
    hostname: Option<String>,
    #[serde(alias = "user")]
    username: Option<String>,
    port: Option<PortValue>,
    #[serde(alias = "identity")]
    key_file: Option<String>,
    key_files: Option<OneOrMany>,
    password: Option<String>,
}

fn default_username() -> String {
    ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "root".to_owned())
}

impl RawServer {
    fn into_config(self, index: usize) -> Result<ServerConfig, String> {
        let hostname = self
            .hostname
            .filter(|h| !h.trim().is_empty())
            .ok_or_else(|| format!("server #{}: 'hostname' is required", index + 1))?;

        let port = match self.port {
            None => 22,
            Some(PortValue::Num(n)) => n,
            Some(PortValue::Text(t)) => t
                .trim()
                .parse()
                .map_err(|_| format!("server #{}: invalid port '{t}'", index + 1))?,
        };
        let port = u16::try_from(port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("server #{}: port {port} out of range (1-65535)", index + 1))?;

        let mut keys: Vec<String> = Vec::new();
        keys.extend(self.key_file);
        match self.key_files {
            Some(OneOrMany::One(k)) => keys.push(k),
            Some(OneOrMany::Many(ks)) => keys.extend(ks),
            None => {}
        }

        Ok(ServerConfig {
            name: self
                .name
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("Server {}", index + 1)),
            hostname,
            username: self
                .username
                .filter(|u| !u.is_empty())
                .unwrap_or_else(default_username),
            port,
            key_files: keys.iter().map(|k| expand_path(k)).collect(),
            password: self
                .password
                .or_else(|| std::env::var("SSHTETHER_PASSWORD").ok())
                .filter(|p| !p.is_empty()),
        })
    }
}

/// Expand `~`, `$VAR`, `${VAR}` (and `%VAR%` on Windows). Unknown variables are
/// left untouched, like Python's `os.path.expandvars`.
pub fn expand_path(input: &str) -> PathBuf {
    let expanded = expand_vars(input);
    if expanded == "~" || expanded.starts_with("~/") || expanded.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            let rest = expanded[1..].trim_start_matches(['/', '\\']);
            return if rest.is_empty() {
                home
            } else {
                home.join(rest)
            };
        }
    }
    PathBuf::from(expanded)
}

fn expand_vars(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
        if c == '$' && i + 1 < chars.len() && chars[i + 1] == '{' {
            if let Some(end) = chars[i + 2..].iter().position(|&c| c == '}') {
                let name: String = chars[i + 2..i + 2 + end].iter().collect();
                match std::env::var(&name) {
                    Ok(v) if !name.is_empty() => out.push_str(&v),
                    _ => out.extend(&chars[i..i + 3 + end]),
                }
                i += 3 + end;
                continue;
            }
        } else if c == '$' && i + 1 < chars.len() && is_name(chars[i + 1]) {
            let len = chars[i + 1..].iter().take_while(|&&c| is_name(c)).count();
            let name: String = chars[i + 1..i + 1 + len].iter().collect();
            match std::env::var(&name) {
                Ok(v) => out.push_str(&v),
                Err(_) => out.extend(&chars[i..i + 1 + len]),
            }
            i += 1 + len;
            continue;
        } else if cfg!(windows) && c == '%' {
            if let Some(end) = chars[i + 1..].iter().position(|&c| c == '%') {
                let name: String = chars[i + 1..i + 1 + end].iter().collect();
                if !name.is_empty() && name.chars().all(is_name) {
                    if let Ok(v) = std::env::var(&name) {
                        out.push_str(&v);
                        i += 2 + end;
                        continue;
                    }
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Candidate config files in priority order.
pub fn config_candidates(explicit: Option<&Path>) -> Vec<PathBuf> {
    if let Some(p) = explicit {
        return vec![p.to_owned()];
    }
    let mut dirs_: Vec<PathBuf> = Vec::new();
    let mut push = |d: PathBuf| {
        if !dirs_.contains(&d) {
            dirs_.push(d);
        }
    };
    if let Some(home) = dirs::home_dir() {
        push(home.join(".config").join("sshtether"));
    }
    if let Some(cfg) = dirs::config_dir() {
        push(cfg.join("sshtether"));
    }

    let mut paths = Vec::new();
    if let Some(p) = std::env::var_os("SSHTETHER_CONFIG").filter(|p| !p.is_empty()) {
        paths.push(PathBuf::from(p));
    }
    for d in dirs_ {
        paths.push(d.join("config.toml"));
        paths.push(d.join("config.json"));
    }
    paths
}

/// Resolve the servers to use from the CLI (`--host`) or a config file.
pub fn load_servers(cli: &Cli) -> Result<Vec<ServerConfig>, ConfigError> {
    if let Some(host) = &cli.host {
        return Ok(vec![ServerConfig {
            name: host.clone(),
            hostname: host.clone(),
            username: cli.user.clone().unwrap_or_else(default_username),
            port: cli.port,
            key_files: cli
                .identity
                .iter()
                .map(|p| expand_path(&p.to_string_lossy()))
                .collect(),
            password: std::env::var("SSHTETHER_PASSWORD")
                .ok()
                .filter(|p| !p.is_empty()),
        }]);
    }

    let candidates = config_candidates(cli.config.as_deref());
    for path in &candidates {
        if !path.is_file() {
            if cli.config.is_some() {
                return Err(ConfigError::NotFound(path.display().to_string()));
            }
            continue;
        }
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Invalid {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        let servers = parse_servers(&text, path.extension().is_some_and(|e| e == "json")).map_err(
            |reason| ConfigError::Invalid {
                path: path.display().to_string(),
                reason,
            },
        )?;
        ui::debug(format!(
            "loaded {} server(s) from {}",
            servers.len(),
            path.display()
        ));
        return Ok(servers);
    }

    Err(ConfigError::NoServers(
        candidates
            .iter()
            .map(|p| format!("  {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n"),
    ))
}

/// Parse a TOML or JSON document into a validated server list.
pub fn parse_servers(text: &str, json: bool) -> Result<Vec<ServerConfig>, String> {
    let root: Value = if json {
        serde_json::from_str(text).map_err(|e| e.to_string())?
    } else {
        let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
        serde_json::to_value(v).map_err(|e| e.to_string())?
    };

    let raw = root
        .get("servers")
        .or_else(|| root.get("server"))
        .cloned()
        .unwrap_or(Value::Array(vec![]));
    let items = match raw {
        Value::Array(a) => a,
        obj @ Value::Object(_) => vec![obj],
        _ => return Err("'server' must be a table or an array of tables".into()),
    };
    if items.is_empty() {
        return Err("no servers defined".into());
    }
    items
        .into_iter()
        .enumerate()
        .map(|(i, v)| {
            let raw: RawServer =
                serde_json::from_value(v).map_err(|e| format!("server #{}: {e}", i + 1))?;
            raw.into_config(i)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toml_array_of_tables() {
        let s = parse_servers(
            r#"
            [[server]]
            name = "A"
            hostname = "10.0.0.1"
            username = "root"
            port = 2222
            key_file = "/k1"
            key_files = ["/k2", "/k3"]

            [[server]]
            host = "10.0.0.2"
            user = "bob"
            "#,
            false,
        )
        .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].port, 2222);
        assert_eq!(
            s[0].key_files,
            [
                PathBuf::from("/k1"),
                PathBuf::from("/k2"),
                PathBuf::from("/k3")
            ]
        );
        assert_eq!(s[1].name, "Server 2");
        assert_eq!(s[1].hostname, "10.0.0.2");
        assert_eq!(s[1].username, "bob");
        assert_eq!(s[1].port, 22);
    }

    #[test]
    fn parses_json_with_servers_key_and_string_port() {
        let s = parse_servers(
            r#"{"servers":[{"hostname":"h","username":"u","port":"2200","key_files":"/k"}]}"#,
            true,
        )
        .unwrap();
        assert_eq!(s[0].port, 2200);
        assert_eq!(s[0].key_files, [PathBuf::from("/k")]);
    }

    #[test]
    fn single_table_is_accepted() {
        let s = parse_servers("[server]\nhostname = \"h\"\n", false).unwrap();
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_servers("", false).unwrap_err().contains("no servers"));
        assert!(parse_servers("[[server]]\nname=\"x\"\n", false)
            .unwrap_err()
            .contains("'hostname' is required"));
        assert!(
            parse_servers("[[server]]\nhostname=\"h\"\nport=70000\n", false)
                .unwrap_err()
                .contains("out of range")
        );
        assert!(parse_servers("[[server]]\nhostname=\"h\"\nport=0\n", false).is_err());
        assert!(
            parse_servers("[[server]]\nhostname=\"h\"\nusernme=\"x\"\n", false)
                .unwrap_err()
                .contains("usernme")
        );
        assert!(parse_servers("{", true).is_err());
    }

    #[test]
    fn password_is_redacted_in_debug() {
        let c = ServerConfig {
            name: "n".into(),
            hostname: "h".into(),
            username: "u".into(),
            port: 22,
            key_files: vec![],
            password: Some("hunter2".into()),
        };
        let d = format!("{c:?}");
        assert!(!d.contains("hunter2"));
        assert!(d.contains("redacted"));
    }

    #[test]
    fn expands_variables_and_tilde() {
        std::env::set_var("SSHTETHER_TEST_DIR", "/opt/keys");
        assert_eq!(
            expand_path("$SSHTETHER_TEST_DIR/id").to_string_lossy(),
            "/opt/keys/id"
        );
        assert_eq!(
            expand_path("${SSHTETHER_TEST_DIR}/id").to_string_lossy(),
            "/opt/keys/id"
        );
        assert_eq!(
            expand_path("$SSHTETHER_SURELY_UNSET/x").to_string_lossy(),
            "$SSHTETHER_SURELY_UNSET/x"
        );
        assert_eq!(
            expand_path("${unterminated").to_string_lossy(),
            "${unterminated"
        );
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_path("~/.ssh/id"), home.join(".ssh").join("id"));
            assert_eq!(expand_path("~"), home);
        }
        assert_eq!(expand_path("~other/x").to_string_lossy(), "~other/x");
    }
}
