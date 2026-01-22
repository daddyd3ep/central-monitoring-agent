# Changelog (CHANGELOG.md)

All notable changes to the Monitoring Agent are documented here.

The format follows **Keep a Changelog** principles.

---

## [1.0.1]

### Added
- CPU model
- CPU Speed
- Agent version headers
- OS version reporting (`PRETTY_NAME`)
- Server uptime reporting
- Public IP auto-detection
- Dry-run installer mode
- Non-interactive token support

### Changed
- Improved Debian 10 compatibility
- Installer reliability on older systems

### Fixed
- Network counter persistence issues

---

## [0.1.0] – Initial Release

### Added
- CPU, RAM, disk, network metrics
- systemd service
- Token-authenticated ingest
- Interactive installer
