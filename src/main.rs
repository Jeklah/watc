//! watc - What Are Those C libraries?
//!
//! A CLI tool for analyzing binaries to determine C library versions used during compilation.
//! Supports ELF and PE formats with multiple analysis methods including symbol extraction,
//! string analysis, and online database queries.

use anyhow::Result;
use clap::Parser;
use watc::cli::{Args, CliApp};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Create and run the CLI application
    let app = CliApp::new(args);
    let exit_code = app.run().await?;

    // Exit with the appropriate code
    std::process::exit(exit_code);
}
