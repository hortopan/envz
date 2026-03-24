use std::collections::HashMap;
use std::env;

const SAFE_VARS: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PATH",
    "PWD",
    "OLDPWD",
    "TERM",
    "TERM_PROGRAM",
    "TERM_SESSION_ID",
    "LANG",
    "TMPDIR",
    "TMP",
    "TEMP",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "HOSTNAME",
    "HOSTTYPE",
    "MACHTYPE",
    "OSTYPE",
    "SHLVL",
    "COLORTERM",
    "NO_COLOR",
    "COLUMNS",
    "LINES",
    "_",
];

const SAFE_PREFIXES: &[&str] = &["XDG_", "LC_"];

pub fn filter_env() -> HashMap<String, String> {
    env::vars()
        .filter(|(key, _)| {
            SAFE_VARS.contains(&key.as_str())
                || SAFE_PREFIXES.iter().any(|prefix| key.starts_with(prefix))
        })
        .collect()
}
