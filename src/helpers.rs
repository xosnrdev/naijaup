#[macro_export]
macro_rules! print_info {
    ($($arg:tt)*) => { println!("\x1b[34m[info]\x1b[0m {}", format!($($arg)*)) } // Blue
}

#[macro_export]
macro_rules! print_warn {
    ($($arg:tt)*) => { println!("\x1b[33m[warn]\x1b[0m {}", format!($($arg)*)) } // Yellow
}

#[macro_export]
macro_rules! print_success {
    ($($arg:tt)*) => { println!("\x1b[32m[ok]\x1b[0m {}", format!($($arg)*)) } // Green
}

#[macro_export]
macro_rules! print_error {
    ($($arg:tt)*) => { eprintln!("\x1b[31m[err]\x1b[0m {}", format!($($arg)*)) } // Red
}
