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

use std::fmt::Display;
use std::sync::OnceLock;

use crate::{log_debug, log_error};

use super::types::{CheckReturn, CheckState};

/// Host state collected once by a dependency, then read by many checks.
///
/// Three conditions are told apart, they used to share the same message:
///
/// - `Some(Ok(value))` the collection succeeded.
/// - `Some(Err(err))` the collection ran and failed, `err` is the reason,
///   usually missing permissions or a missing binary.
/// - `None` the collection never ran, a dependency is missing from the check.
pub struct State<T> {
    inner: OnceLock<Result<T, String>>,
    /// Name of the collected state, used to build messages.
    label: &'static str,
}

impl<T> State<T> {
    /// Create an empty state, `label` names it in the messages.
    pub const fn new(label: &'static str) -> Self {
        State {
            inner: OnceLock::new(),
            label,
        }
    }

    /// Collect the state, this is the body of a `DependencyFn`.
    pub fn init<F, E>(&self, fetch: F)
    where
        F: FnOnce() -> Result<T, E>,
        E: Display,
    {
        self.inner.get_or_init(|| match fetch() {
            Ok(value) => {
                log_debug!("initialized {}", self.label);
                Ok(value)
            }
            Err(err) => {
                log_error!("failed to initialize {}: {}", self.label, err);
                Err(err.to_string())
            }
        });
    }

    /// Borrow the collected state, or the reason it is unavailable.
    pub fn try_get(&self) -> Result<&T, String> {
        match self.inner.get() {
            Some(Ok(value)) => Ok(value),
            Some(Err(err)) => Err(format!("{}: {}", self.label, err)),
            None => Err(format!(
                "internal error: {} was never initialized, a dependency is missing",
                self.label
            )),
        }
    }

    /// Same as [`State::try_get`], with the reason as a ready to use warning.
    pub fn get(&self) -> Result<&T, CheckReturn> {
        self.try_get()
            .map_err(|err| (CheckState::Warning, Some(err)))
    }

    /// Run `check` on the collected state.
    ///
    /// When the state is unavailable the reason is returned as a warning, so
    /// checks do not have to handle the missing state themselves.
    pub fn with<F>(&self, check: F) -> CheckReturn
    where
        F: FnOnce(&T) -> CheckReturn,
    {
        match self.get() {
            Ok(value) => check(value),
            Err(warning) => warning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_never_initialized() {
        let state: State<u8> = State::new("test state");

        let err = state.try_get().unwrap_err();
        assert!(err.contains("test state"), "{:?}", err);
        assert!(err.contains("never initialized"), "{:?}", err);

        let (state_result, message) = state.with(|_| (CheckState::Pass, None));
        assert_eq!(state_result, CheckState::Warning);
        assert!(message.unwrap().contains("never initialized"));
    }

    #[test]
    fn test_state_init_failure_keeps_reason() {
        let state: State<u8> = State::new("test state");
        state.init(|| Err::<u8, String>("permission denied".to_string()));

        let (state_result, message) = state.with(|_| (CheckState::Pass, None));
        assert_eq!(state_result, CheckState::Warning);
        assert_eq!(
            message.unwrap(),
            "test state: permission denied".to_string()
        );
    }

    #[test]
    fn test_state_init_success() {
        let state: State<u8> = State::new("test state");
        state.init(|| Ok::<u8, String>(42));

        assert_eq!(state.try_get().unwrap(), &42);
        assert_eq!(
            state.with(|value| (CheckState::Pass, Some(value.to_string()))),
            (CheckState::Pass, Some("42".to_string()))
        );
    }

    #[test]
    fn test_state_init_runs_once() {
        let state: State<u8> = State::new("test state");
        state.init(|| Ok::<u8, String>(1));
        state.init(|| Ok::<u8, String>(2));

        assert_eq!(state.try_get().unwrap(), &1);
    }
}
