//! Line framing with a hard size limit.
//!
//! The reader never buffers more than the limit: once a line passes it, the
//! rest of that line is discarded as it arrives and the line is reported as
//! too large. The next line is read normally, so a single oversized frame
//! does not desynchronise the stream.

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// One line without its terminator (`\n` or `\r\n`).
    Line(Vec<u8>),
    /// A line longer than the limit. Its content was discarded.
    TooLarge,
}

#[derive(Debug)]
pub struct FrameReader<R> {
    reader: BufReader<R>,
    max_len: usize,
    buffer: Vec<u8>,
    discarding: bool,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(reader: R, max_len: usize) -> Self {
        Self::with_capacity(reader, max_len, 8 * 1024)
    }

    pub fn with_capacity(reader: R, max_len: usize, capacity: usize) -> Self {
        Self {
            reader: BufReader::with_capacity(capacity, reader),
            max_len,
            buffer: Vec::new(),
            discarding: false,
        }
    }

    /// Next frame, or `None` at end of stream. An unterminated final line is
    /// returned as a frame; it is still subject to the limit.
    ///
    /// Cancel-safe: if the future is dropped, bytes already consumed stay in
    /// the internal buffer and the next call continues the same line.
    pub async fn next_frame(&mut self) -> std::io::Result<Option<Frame>> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                if self.discarding {
                    self.discarding = false;
                    return Ok(Some(Frame::TooLarge));
                }
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(self.take_line()));
            }

            let newline = available.iter().position(|&byte| byte == b'\n');
            let chunk = newline.unwrap_or(available.len());
            let consumed = newline.map_or(chunk, |at| at + 1);

            if !self.discarding {
                if self.buffer.len() + chunk > self.max_len + 1 {
                    // `+ 1` leaves room for a `\r` that is stripped below.
                    self.discarding = true;
                    self.buffer.clear();
                } else {
                    self.buffer.extend_from_slice(&available[..chunk]);
                }
            }
            self.reader.consume(consumed);

            if newline.is_some() {
                if self.discarding {
                    self.discarding = false;
                    return Ok(Some(Frame::TooLarge));
                }
                return Ok(Some(self.take_line()));
            }
        }
    }

    fn take_line(&mut self) -> Frame {
        let mut line = std::mem::take(&mut self.buffer);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.len() > self.max_len {
            return Frame::TooLarge;
        }
        Frame::Line(line)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    async fn frames(input: &[u8], max_len: usize, capacity: usize) -> Vec<Frame> {
        let mut reader = FrameReader::with_capacity(input, max_len, capacity);
        let mut out = Vec::new();
        while let Some(frame) = reader.next_frame().await.unwrap() {
            out.push(frame);
        }
        out
    }

    fn line(text: &str) -> Frame {
        Frame::Line(text.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn splits_lines_and_strips_terminators() {
        assert_eq!(
            frames(b"a\nbc\r\n\nlast", 8, 2).await,
            [line("a"), line("bc"), line(""), line("last")]
        );
    }

    #[tokio::test]
    async fn oversized_line_is_reported_and_stream_resynchronises() {
        let input = b"ok\n0123456789abcdef\nnext\n";
        assert_eq!(
            frames(input, 8, 3).await,
            [line("ok"), Frame::TooLarge, line("next")]
        );
    }

    #[tokio::test]
    async fn limit_is_inclusive_and_ignores_carriage_return() {
        assert_eq!(
            frames(b"12345678\r\n123456789\n", 8, 4).await,
            [line("12345678"), Frame::TooLarge]
        );
    }

    #[tokio::test]
    async fn oversized_unterminated_tail_is_too_large() {
        assert_eq!(frames(b"0123456789", 4, 2).await, [Frame::TooLarge]);
    }

    fn reference(input: &[u8], max_len: usize) -> Vec<Frame> {
        let mut out = Vec::new();
        let mut parts: Vec<&[u8]> = input.split(|&b| b == b'\n').collect();
        if parts.last().is_some_and(|tail| tail.is_empty()) {
            parts.pop();
        }
        for part in parts {
            let part = part.strip_suffix(b"\r").unwrap_or(part);
            out.push(if part.len() > max_len {
                Frame::TooLarge
            } else {
                Frame::Line(part.to_vec())
            });
        }
        out
    }

    proptest! {
        /// Whatever the chunking, the reader agrees with a simple reference
        /// splitter.
        #[test]
        fn matches_reference_for_any_chunking(
            input in proptest::collection::vec(
                prop_oneof![Just(b'\n'), Just(b'\r'), Just(b'a'), any::<u8>()], 0..200),
            max_len in 0usize..20,
            capacity in 1usize..16,
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let actual = runtime.block_on(frames(&input, max_len, capacity));
            prop_assert_eq!(actual, reference(&input, max_len));
        }
    }
}
