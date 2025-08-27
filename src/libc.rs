//! Libc database interaction module
//!
//! This module provides functionality for querying the libc.blukat.me database
//! and matching symbols to determine C library versions.

pub mod api;
pub mod matcher;

pub use api::{ApiConfig, LibcApiClient, LibcMatch, LibcResponse, QueryInfo, prepare_symbols_for_query};
pub use matcher::{DetectionResult, DetectionStrategy, LibcMatcher, LibcMatchWithScore};

use anyhow::Result;

/// Convenience function to create a default libc matcher
pub fn create_matcher() -> Result<LibcMatcher> {
    let api_client = LibcApiClient::new()?;
    Ok(LibcMatcher::new(api_client))
}

/// Convenience function to create a matcher with custom API configuration
pub fn create_matcher_with_config(config: ApiConfig) -> Result<LibcMatcher> {
    let api_client = LibcApiClient::with_config(config)?;
    Ok(LibcMatcher::new(api_client))
}

/// Test if the libc API is accessible
pub async fn test_api_connection() -> Result<bool> {
    let client = LibcApiClient::new()?;
    client.test_connection().await
}
