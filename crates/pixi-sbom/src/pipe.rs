//! Standard output that a reader may close early (#28).
//!
//! `pixi sbom --doctor | head -12` closes the pipe after twelve lines. The rest of the output has
//! nowhere to go, which is the reader's choice rather than a failure, so it is dropped and the run
//! goes on: the exit code is still the one `--doctor` or a gate decides, and nothing is printed
//! about the pipe.

use std::io::{ErrorKind, Write};

/// A writer that, once a write or flush finds the pipe closed, accepts and drops everything
/// after it. Every other error is passed on.
pub struct Quiet<W: Write> {
    inner: W,
    closed: bool,
}

impl<W: Write> Quiet<W> {
    /// Wrap `inner`.
    pub fn new(inner: W) -> Self {
        Quiet { inner, closed: false }
    }

    /// Whether the reader has closed the pipe.
    pub fn closed(&self) -> bool {
        self.closed
    }

    fn closing(&mut self, err: &std::io::Error) -> bool {
        if err.kind() == ErrorKind::BrokenPipe {
            if !self.closed {
                tracing::debug!("stdout was closed by its reader; the rest of the output is dropped");
            }
            self.closed = true;
        }
        self.closed
    }
}

impl<W: Write> Write for Quiet<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.closed {
            return Ok(buf.len());
        }
        match self.inner.write(buf) {
            Err(err) if self.closing(&err) => Ok(buf.len()),
            other => other,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.closed {
            return Ok(());
        }
        match self.inner.flush() {
            Err(err) if self.closing(&err) => Ok(()),
            other => other,
        }
    }
}

/// Standard output, buffered and quiet about a closed pipe.
pub fn stdout() -> std::io::BufWriter<Quiet<std::io::StdoutLock<'static>>> {
    std::io::BufWriter::new(Quiet::new(std::io::stdout().lock()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Takes `room` bytes, then reports the pipe closed.
    struct Pipe {
        taken: Vec<u8>,
        room: usize,
        other: bool,
    }

    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.other {
                return Err(std::io::Error::other("disk full"));
            }
            if self.taken.len() >= self.room {
                return Err(ErrorKind::BrokenPipe.into());
            }
            let n = buf.len().min(self.room - self.taken.len());
            self.taken.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.taken.len() >= self.room {
                return Err(ErrorKind::BrokenPipe.into());
            }
            Ok(())
        }
    }

    #[test]
    fn a_closed_pipe_ends_the_output_quietly_and_other_errors_still_fail() {
        let mut quiet = Quiet::new(Pipe {
            taken: Vec::new(),
            room: 5,
            other: false,
        });
        writeln!(quiet, "first line").unwrap();
        writeln!(quiet, "second line").unwrap();
        quiet.flush().unwrap();
        assert!(quiet.closed());
        assert_eq!(quiet.inner.taken, b"first");

        let mut open = Quiet::new(Pipe {
            taken: Vec::new(),
            room: 100,
            other: false,
        });
        writeln!(open, "fits").unwrap();
        open.flush().unwrap();
        assert!(!open.closed());

        let mut failing = Quiet::new(Pipe {
            taken: Vec::new(),
            room: 100,
            other: true,
        });
        let err = write!(failing, "x").unwrap_err();
        assert_eq!(err.to_string(), "disk full");
        assert!(!failing.closed());
    }
}
