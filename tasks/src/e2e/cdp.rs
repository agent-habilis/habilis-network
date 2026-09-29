//! The CDP cells of the matrix: one Chrome for Testing window per cell,
//! driven through [`crate::util::cdp`], harvesting the table its page
//! publishes. Every other browser takes the `WebDriver` backend; the pressure
//! axis is created inside the page either way, so no browser is short-changed
//! by which transport drives it.

use std::time::Duration;

use crate::util::cdp::Browser;

use super::{Harvest, Skip, server};

/// Run one cell and harvest what the page published.
pub(super) fn run(pressure: u32, timeout: Duration) -> Result<Harvest, Skip> {
    let browser = Browser::launch()?;
    let version = browser.version();

    // The pressure level rides the URL: the page creates the contention itself,
    // and its deadlines have to scale with it or a slow cell reads as a stalled
    // one.
    let url = format!("{}/?pressure={pressure}", server::URL);
    browser.navigate(&url);
    let published = browser.wait_for(super::DONE_SELECTOR, timeout);

    Ok(Harvest {
        table: browser.evaluate(super::TABLE_EXPRESSION),
        failed: super::normalise_failed(&browser.evaluate(super::FAILED_EXPRESSION)),
        version,
        published,
    })
}
