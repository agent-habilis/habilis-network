use std::fmt;
use wasm_bindgen::prelude::JsValue;

pub(crate) fn err(context: &str, error: &impl fmt::Display) -> JsValue {
    JsValue::from_str(&format!("failed to {context}: {error}"))
}

pub(crate) fn describe(error: &JsValue) -> String {
    error
        .as_string()
        .unwrap_or_else(|| format!("{:?}", error.clone()))
}
