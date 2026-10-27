# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org).

<!--
Note: In this file, do not use the hard wrap in the middle of a sentence for compatibility with GitHub comment style markdown rendering.
-->

## [Unreleased]

### Added

- Add tag intersection to `--tags` and `--tags-exclude`, `+` joins the tags of a group
- Add an extended guide to `raudit --help`
- Add sudo checks `SUD_012`, `SUD_204`, and `SUD_205`

### Changed

- Update IDs for some sudo file-system checks
- Update the human readable output to highlight commands and files

## [0.37.0] - 2026-10-24

### Added

- Add `check::State` for host state collected as dependency that keeps the reason of its failure to add to warnings in checks

### Changed

- Update init error messages to be more accurate

## [0.36.1] - 2026-10-22

### Added

- Add sysctl checks `SYS_106` to `SYS_217`

### Changed

- Update ID, description, and severity of some existing sysctl rules

### Fixed

- Fix error in sysctl rules where some max values did not have min, add range

## [0.36.0] - 2026-10-21

### Added

- Add modprobe checks `KMD_001` to `KMD_004` for `/etc/modprobe.d` directory and files ownership and permissions
- Add warning on modprobe rules when a module is compiled in the kernel, and thus cannot be blacklisted or disabled
- Add kernel build config fallback sources `/boot/config-$(uname -r)` and `/proc/config.gz`

### Changed

- Update all the rules of modprobe, don't use a macro to generate them so they have consistent IDs
- Small refactor, removed `pub` from struct in modules

### Fixed

- Fix modprobe module, complete refactor, now work the way modprobe parses the config files, including glob pattern (?/*)
- Fix the kernel boot params `/proc/cmdline` parser

## [0.35.3] - 2026-10-20

### Added

- Add `base` helpers form permission checks with `_or_stricter` suffix to allow for stricter permissions

### Fixed

- Fixed permission checks on some rules

## [0.35.2] - 2026-10-19

### Added

- Add release CI support for musl
- Add release CI support for ARM

### Changed

- Update CI to pin actions version with commit hash

## [0.35.1] - 2026-10-19

### Added

- Add user checks `USR_017` and `USR_018`
- Add login_defs checks `LDF_013`

### Changed

- Changed the format for the human readable output
- Change `SHL_001` timeout script
- Optimized the release build for size

### Fixed

- Fixed a bug where mount file was missing character escaping
- Fixed a parsing error on hosts file

## [0.35.0] - 2026-10-14

### Added

- Add Systemd check `systemd_unit_active`
- Add Secure Boot module
- Add Secure Boot check `SCB_001`
- Add LUKS check `MNT_100`
- Add descriptions to kernel params checks

### Changed

- Updated severity level of some checks
- Skip systemd checks when not used

### Fixed

- Fixed apt checks for boolean values
- Fixed status on some checks with valid defaults instead of error

## [0.34.0] - 2026-10-10

### Added

- Add SSH checks `SSH_054` to `SSH_056`
- Add user checks `USR_012` to `USR_016`
- Add system checks `SYT_002` to `SYT_009`
- Add audit checks `AUD_101` to `AUD_108`
- Add skip condition for `EXP_001`

### Fixed

- Fixed end-to-end tests
- Fixed checks `APT_100` to `APT_103`
- Fixed duplicate check ID `KNP_063`

## [0.33.0] - 2026-09-17

- Add checks `CNT_032` and `CNT_507`
- Add or improve checks descriptions
- Add KSPP tags
- Update some severity levels
- Remove duplicate checks

## [0.32.3] - 2026-05-08

- Update Docker checks to verify from `docker info` directly
- Fix check for socket files permissions and owner not working
- Internal refactoring, update checks

## [0.32.2] - 2026-05-06

- Add rules `HST_003` to `HST_007`
- Add rule `EXP_001`
- Add exploit mitigation rules
- Add descriptions to rules
- Update some rules levels
- Add UID/GID resolution helper function
- Internal refactoring, update project layout

## [0.32.1] - 2026-05-01

- Add `--no-skip` CLI flag to disable automatic check skipping

[0.36.1]: https://github.com/deoktr/raudit/releases/tag/v0.36.1
[0.36.0]: https://github.com/deoktr/raudit/releases/tag/v0.36.0
[0.35.3]: https://github.com/deoktr/raudit/releases/tag/v0.35.3
[0.35.2]: https://github.com/deoktr/raudit/releases/tag/v0.35.2
[0.35.1]: https://github.com/deoktr/raudit/releases/tag/v0.35.1
[0.35.0]: https://github.com/deoktr/raudit/releases/tag/v0.35.0
[0.34.0]: https://github.com/deoktr/raudit/releases/tag/v0.34.0
[0.33.0]: https://github.com/deoktr/raudit/releases/tag/v0.33.0
[0.32.3]: https://github.com/deoktr/raudit/releases/tag/v0.32.3
[0.32.2]: https://github.com/deoktr/raudit/releases/tag/v0.32.2
[0.32.1]: https://github.com/deoktr/raudit/releases/tag/v0.32.1
