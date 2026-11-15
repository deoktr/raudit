/*
 * rAudit, a Linux security auditing toolkit
 * Copyright (C) 2024 - 2025  deoktr
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Host data collection, one module per subsystem inspected by the checks.

pub mod apparmor;
pub mod apt;
pub mod arch;
pub mod audit;
pub mod base;
pub mod bin;
pub mod clamav;
pub mod cron;
pub mod docker;
pub mod gdm;
pub mod group;
pub mod grub;
pub mod hosts;
pub mod kconfig;
pub mod kernel;
pub mod login_defs;
pub mod malloc;
pub mod modprobe;
pub mod mount;
pub mod nginx;
pub mod os;
pub mod pam;
pub mod podman;
pub mod ps;
pub mod secureboot;
pub mod shell;
pub mod sshd;
pub mod sudo;
pub mod sysctl;
pub mod systemd;
pub mod uptime;
pub mod users;
pub mod utils;
