//! sudoubt: sudo with trust issues. See README.md for the design.
//!
//! This is a placeholder so the release pipeline can be tested. It does
//! nothing and always fails with exit code 1.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("sudoubt: not implemented yet");
    println!("{{\n  \"ok\": false,\n  \"exit_code\": 1,\n  \"error\": \"not implemented yet\"\n}}");
    ExitCode::from(1)
}
