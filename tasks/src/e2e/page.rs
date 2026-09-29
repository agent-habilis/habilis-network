//! One browser tab behind whichever driver reaches it, for the suites that
//! drive a page themselves (mesh, chat, stream).

use std::time::Duration;

use crate::util::cdp;
use crate::util::page::{Evaluate, call_page_within};
use crate::util::webdriver;

/// How long a page call may take to settle before it is reported as never
/// having done so.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// One browser on a page, behind whichever driver reaches it.
pub(crate) enum Page {
    Cdp(Box<cdp::Browser>),
    WebDriver(webdriver::Session),
}

impl Page {
    pub(crate) fn navigate(&self, url: &str) {
        match self {
            Self::Cdp(browser) => browser.navigate(url),
            Self::WebDriver(session) => session.navigate(url),
        }
    }

    /// [`Page::navigate`], recording the console for `window` where the
    /// driver can. `WebDriver` has no console stream, so it only navigates.
    pub(crate) fn navigate_watching_console(&self, url: &str, window: Duration) {
        match self {
            Self::Cdp(browser) => browser.navigate_watching_console(url, window),
            Self::WebDriver(session) => session.navigate(url),
        }
    }

    /// What [`Page::navigate_watching_console`] recorded; blocks until its
    /// window is over.
    pub(crate) fn console(&self) -> String {
        match self {
            Self::Cdp(browser) => browser.console(),
            Self::WebDriver(_) => String::new(),
        }
    }

    /// Evaluate a JS expression (no `return`), reading its value as a string.
    pub(crate) fn evaluate(&self, expression: &str) -> String {
        match self {
            Self::Cdp(browser) => browser.evaluate(expression),
            Self::WebDriver(session) => session.execute(&format!("return ({expression});")),
        }
    }

    pub(crate) fn version(&self) -> String {
        match self {
            Self::Cdp(browser) => browser.version(),
            Self::WebDriver(session) => session.version(),
        }
    }
}

impl Evaluate for Page {
    fn evaluate(&self, expression: &str) -> String {
        Page::evaluate(self, expression)
    }
}

/// [`call_page_within`] with the suites' default timeout.
pub(crate) fn call_page(page: &Page, object: &str, call: &str) -> Result<String, String> {
    call_page_within(page, object, call, CALL_TIMEOUT)
}

pub(crate) fn urlencode(raw: &str) -> String {
    raw.replace('%', "%25")
        .replace('&', "%26")
        .replace('+', "%2B")
        .replace('#', "%23")
}
