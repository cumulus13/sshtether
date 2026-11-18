# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-18

### Added
- Initial Rust port of the Python `rcmd.py` script.
- Full PTY session with raw-mode keyboard forwarding, window-resize propagation,
  UTF-8 locale export and OpenSSH-style escapes (`~.`, `~?`, `~~`).
- Auto-reconnect with multi-server failover and jittered exponential backoff.
- Dead-peer detection: SSH heartbeat plus TCP keepalive / `TCP_USER_TIMEOUT`.
- Host-key verification (`accept-new`, `strict`, `insecure`); a changed key is
  always refused.
- Authentication via key files, ssh-agent (Unix socket, Windows OpenSSH pipe and
  Pageant), default `~/.ssh` keys and password.
- `--persist tmux|screen` to keep the command alive on the server.
- **Single-instance guarantee**: a reconnect first stops the lingering process of
  the previous connection of the same run, so duplicate processes can never
  accumulate (disable with `--allow-duplicates`).
- TOML and JSON configuration with strict validation.

### Changed (compared to `rcmd.py`)
- No hard-coded default servers: pass `--host` or provide a config file.
- Environment variables are prefixed `SSHTETHER_` instead of `RCMD_`.
- Host-key fingerprints are SHA-256 instead of MD5.
