//! Test-only and headless platform adapter boundary.

use super::ports::PlatformPort;

#[derive(Default)]
pub(crate) struct MockPlatformPort;

impl PlatformPort for MockPlatformPort {}
