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

//! Security checks, grouped by the subsystem they verify.

pub mod apparmor;
pub mod apt;
pub mod audit;
pub mod bin;
pub mod clamav;
pub mod cron;
pub mod docker;
pub mod exploit;
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
pub mod pam;
pub mod podman;
pub mod secureboot;
pub mod shell;
pub mod sshd;
pub mod sudo;
pub mod sysctl;
pub mod system;
pub mod systemd;
pub mod uptime;
pub mod user;

/// Register every check of the toolkit.
pub fn add_all_checks() {
    apparmor::add_checks();
    apt::add_checks();
    audit::add_checks();
    bin::add_checks();
    clamav::add_checks();
    cron::add_checks();
    docker::add_checks();
    exploit::add_checks();
    gdm::add_checks();
    group::add_checks();
    grub::add_checks();
    hosts::add_checks();
    kconfig::add_checks();
    kernel::add_checks();
    login_defs::add_checks();
    malloc::add_checks();
    modprobe::add_checks();
    mount::add_checks();
    nginx::add_checks();
    pam::add_checks();
    podman::add_checks();
    secureboot::add_checks();
    shell::add_checks();
    sshd::add_checks();
    sudo::add_checks();
    sysctl::add_checks();
    system::add_checks();
    systemd::add_checks();
    uptime::add_checks();
    user::add_checks();
}
