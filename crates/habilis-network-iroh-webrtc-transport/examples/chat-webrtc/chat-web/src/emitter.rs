use crate::Event;
use js_sys::JSON;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::JsValue;
use web_sys::console;

#[derive(Debug, Clone)]
pub(crate) struct Emitter {
    callback: Rc<js_sys::Function>,
    /// Set once a terminal [`Event::Closed`] has gone out, so a reader and a
    /// writer failing together do not report the link dying twice.
    closed: Rc<RefCell<bool>>,
}

impl Emitter {
    pub(crate) fn new(callback: js_sys::Function) -> Self {
        Self {
            callback: Rc::new(callback),
            closed: Rc::new(RefCell::new(false)),
        }
    }

    pub(crate) fn status(&self, text: &str) {
        self.send(&Event::Status {
            text: text.to_owned(),
        });
    }

    pub(crate) fn send(&self, event: &Event) {
        if matches!(event, Event::Closed { .. }) {
            let mut closed = self.closed.borrow_mut();
            if *closed {
                return;
            }
            *closed = true;
        }
        let Ok(json) = serde_json::to_string(event) else {
            return;
        };
        let Ok(value) = JSON::parse(&json) else {
            return;
        };
        if let Err(error) = self.callback.call1(&JsValue::NULL, &value) {
            console::warn_1(&error);
        }
    }
}
