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

use crate::{base, check};

/// Ensure automatic logout from shells is configured.
///
/// In, /etc/profile.d/shell-timeout.sh:
/// ```bash
/// TMOUT="$(( 60*10 ))";
/// [ -z "$DISPLAY" ] && export TMOUT;
/// case $( /usr/bin/tty ) in
/// 	/dev/tty[0-9]*) export TMOUT;;
/// esac
/// ```
///
/// <https://wiki.archlinux.org/title/Security#Automatic_logout>
pub fn check_shell_timeout() -> check::CheckReturn {
    // FIXME: allow for comments, at least the the top
    base::check_file_content_regex(
        "/etc/profile.d/shell-timeout.sh",
        r#"TMOUT=.*;\n\[ -z "\$DISPLAY" ] && export TMOUT;\ncase \$\( /usr/bin/tty \) in\n[ \t]*/dev/tty\[0\-9\]\*\) export TMOUT;;\nesac"#,
    )
}
