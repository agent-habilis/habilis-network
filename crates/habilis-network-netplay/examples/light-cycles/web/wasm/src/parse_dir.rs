use crate::dir::Dir;
use crate::js_error;
use wasm_bindgen::prelude::JsValue;

pub(crate) fn parse_dir(s: &str) -> Result<Dir, JsValue> {
    match s.to_ascii_lowercase().as_str() {
        "up" => Ok(Dir::Up),
        "down" => Ok(Dir::Down),
        "left" => Ok(Dir::Left),
        "right" => Ok(Dir::Right),
        other => Err(js_error::to_js_error(format!("unknown direction: {other}"))),
    }
}
