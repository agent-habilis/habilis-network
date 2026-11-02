use std::fmt;
use wasm_bindgen::prelude::JsValue;

pub(crate) fn to_js_error(err: impl fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}
