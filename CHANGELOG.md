# Changelog

All notable changes to Khao2 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-04

### Added
- Initial public release
- `k2 dig` command for image steganalysis
- `k2 get` command to retrieve scan results
- `k2 token set/get` for API token management
- `k2 endpoint set/get` for API endpoint configuration
- `k2 account` for account information
- `k2 quota` for usage quota display
- Real-time scan progress with `--watch` flag
- JSON output format support
- Secure local configuration storage

### Security
- Tokens stored securely in `~/.khao2/forensicwaffle`
- HTTPS-only API communication
