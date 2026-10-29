//! Bounded line reads — cap a single `read_line` so no input can grow an
//! unbounded buffer (the "all I/O is bounded" invariant). Used for stdin
//! and the IPC socket.

use tokio::io::{self, AsyncBufRead, AsyncBufReadExt};

/// Outcome of [`read_bounded_line`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum LineRead {
    /// Stream closed with nothing buffered.
    Eof,
    /// A complete line (trailing `\n` excluded), within the cap.
    Line(String),
    /// The line exceeded `max` bytes. It was drained through its newline
    /// so the stream stays aligned to the next line, then dropped.
    TooLong,
}

/// Read one `\n`-terminated line, accumulating at most `max` bytes. Uses
/// `fill_buf`/`consume`, so peak memory is `max` + one buffered chunk:
/// once `max` is reached before the newline, further bytes are consumed
/// and discarded until the newline, then `TooLong` is returned.
/// # Errors
/// Propagates the reader's I/O errors.
pub async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<LineRead> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut overflow = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            // EOF.
            if overflow {
                return Ok(LineRead::TooLong);
            }
            if buffer.is_empty() {
                return Ok(LineRead::Eof);
            }
            return Ok(finish(&buffer));
        }
        if let Some(position) = chunk.iter().position(|&byte| byte == b'\n') {
            if !overflow && would_overflow(&mut buffer, &chunk[..position], max) {
                overflow = true;
            }
            reader.consume(position + 1);
            return Ok(if overflow {
                LineRead::TooLong
            } else {
                finish(&buffer)
            });
        }
        // No newline in this chunk: accumulate up to the cap, consume all.
        let len = chunk.len();
        if !overflow && would_overflow(&mut buffer, chunk, max) {
            overflow = true;
        }
        reader.consume(len);
    }
}

/// Append `piece` to `buf` if it fits within `max`; otherwise leave `buf`
/// untouched and report the overflow. Split out of [`read_bounded_line`] so
/// the overflow-check/extend branch isn't nested inside its `if let`/`if`.
fn would_overflow(buffer: &mut Vec<u8>, piece: &[u8], max: usize) -> bool {
    let remaining = max.saturating_sub(buffer.len());
    if piece.len() > remaining {
        return true;
    }
    buffer.extend_from_slice(piece);
    false
}

fn finish(buffer: &[u8]) -> LineRead {
    // Callers `.trim()`; lossy keeps us robust to non-UTF-8 input.
    LineRead::Line(String::from_utf8_lossy(buffer).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{LineRead, io, read_bounded_line};

    #[test]
    fn reads_lines_then_eof() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let data = b"hello\nworld\n";
            let mut reader = io::BufReader::new(&data[..]);
            assert!(
                matches!(
                    read_bounded_line(&mut reader, 100).await.unwrap(),
                    LineRead::Line(line) if line == "hello"
                ),
                "the first line is read"
            );
            assert!(
                matches!(
                    read_bounded_line(&mut reader, 100).await.unwrap(),
                    LineRead::Line(line) if line == "world"
                ),
                "the second line is read"
            );
            assert!(
                matches!(
                    read_bounded_line(&mut reader, 100).await.unwrap(),
                    LineRead::Eof
                ),
                "the stream ends after the last line"
            );
        });
    }

    #[test]
    fn over_long_line_dropped_then_stream_realigns() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let data = b"thisaverylongline\nok\n";
            let mut reader = io::BufReader::new(&data[..]);
            assert!(
                matches!(
                    read_bounded_line(&mut reader, 4).await.unwrap(),
                    LineRead::TooLong
                ),
                "an over-long line is dropped and the stream realigns"
            );
            assert!(
                matches!(read_bounded_line(&mut reader, 100).await.unwrap(), LineRead::Line(line) if line == "ok"),
                "the next line must be read intact after dropping the oversize one"
            );
        });
    }

    #[test]
    fn final_line_without_newline_is_delivered() {
        ::habilis_network_test_tracing::run(::habilis_network_test_tracing::init(), async {
            let data = b"tail";
            let mut reader = io::BufReader::new(&data[..]);
            assert!(
                matches!(
                    read_bounded_line(&mut reader, 100).await.unwrap(),
                    LineRead::Line(line) if line == "tail"
                ),
                "a final line without a newline is delivered"
            );
        });
    }
}
