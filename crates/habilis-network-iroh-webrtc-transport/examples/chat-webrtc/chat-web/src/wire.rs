use crate::js_error;
use chat_proto::{FRAME_HEADER_LEN, decode_body, decode_frame_len, encode_frame};
use habilis_network_iroh_webrtc_transport::iroh::endpoint;
use habilis_network_iroh_webrtc_transport::iroh::endpoint::RecvStream;
use serde::{Serialize, de};
use wasm_bindgen::prelude::JsValue;

pub(crate) async fn write_msg<T: Serialize>(
    send: &mut endpoint::SendStream,
    message: &T,
) -> Result<(), JsValue> {
    let frame = encode_frame(message).map_err(|error| js_error::err("encode a frame", &error))?;
    send.write_all(&frame)
        .await
        .map_err(|error| js_error::err("write a frame", &error))?;
    Ok(())
}

pub(crate) async fn read_msg<T: de::DeserializeOwned>(recv: &mut RecvStream) -> Result<T, JsValue> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    recv.read_exact(&mut header)
        .await
        .map_err(|error| js_error::err("read a frame header", &error))?;
    let len = decode_frame_len(header).map_err(|error| js_error::err("frame length", &error))?;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|error| js_error::err("read a frame body", &error))?;
    decode_body(&body).map_err(|error| js_error::err("decode a frame", &error))
}

// ── talking to JS ────────────────────────────────────────────────────────────
