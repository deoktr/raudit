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
mod apt;
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
mod hosts;
mod kconfig;
mod kernel;
mod logger;
mod login_defs;
mod malloc;
mod modprobe;
mod mount;
mod pam;
mod podman;
mod ps;
mod shell;
mod sshd;
mod sudo;
mod sysctl;
mod systemd;
mod uptime;
mod users;
mod utils;

mod rules {
    pub mod apparmor;
    pub mod apt;
    pub mod audit;
    pub mod clamav;
    pub mod docker;
    pub mod gdm;
    pub mod group;
    pub mod grub;
    pub mod hosts;
    pub mod kernel;
    pub mod kernel_params;
    pub mod login_defs;
    pub mod malloc;
    pub mod modprobe;
    pub mod mount;
    pub mod pam;
    pub mod podman;
    pub mod shell;
    pub mod sshd;
    pub mod sudo;
    pub mod sysctl;
    pub mod system;
    pub mod systemd;
    pub mod uptime;
    pub mod user;
}

fn main() {
    cli::cli()
}
