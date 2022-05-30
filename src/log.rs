use std::{
    fmt::Arguments,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

// These match syslog severity levels.
pub const LEVEL_DEBUG: u8 = 7;
pub const LEVEL_INFO: u8 = 6;
pub const LEVEL_WARNING: u8 = 4;
pub const LEVEL_ERROR: u8 = 3;

pub static LEVEL: AtomicU8 = AtomicU8::new(LEVEL_WARNING);
pub static FMT_SYSLOG: AtomicBool = AtomicBool::new(false);

pub fn print(syslog_level: u8, args: Arguments) {
    if LEVEL.load(Ordering::Relaxed) >= syslog_level {
        if FMT_SYSLOG.load(Ordering::Relaxed) {
            // This prefix is picked up by systemd and syslog.
            eprintln!("<{}>{}", syslog_level, args);
        } else {
            eprintln!("{}", args);
        }
    }
}

macro_rules! debug {
    ($($arg:tt)*) => {{
        $crate::log::print($crate::log::LEVEL_DEBUG, format_args!($($arg)*));
    }}
}

macro_rules! info {
    ($($arg:tt)*) => {{
        $crate::log::print($crate::log::LEVEL_INFO, format_args!($($arg)*));
    }}
}

macro_rules! warning {
    ($($arg:tt)*) => {{
        $crate::log::print($crate::log::LEVEL_WARNING, format_args!($($arg)*));
    }}
}

macro_rules! error {
    ($($arg:tt)*) => {{
        $crate::log::print($crate::log::LEVEL_ERROR, format_args!($($arg)*));
    }}
}

pub(crate) use {debug, error, info, warning};
