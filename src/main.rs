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

mod apparmor;
mod audit;
mod base;
mod check;
mod clamav;
mod cli;
mod config;
mod consts;
mod docker;
mod gdm;
mod group;
mod grub;
mod kconfig;
mod kernel;
mod logger;
mod login_defs;
mod malloc;
mod modprobe;
mod mount;
mod pam;
mod ps;
mod shell;
mod sshd;
mod sudo;
mod sysctl;
mod systemd;
mod users;
mod utils;

fn main() {
    cli::cli()
}
