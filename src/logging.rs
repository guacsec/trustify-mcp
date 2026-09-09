use std::fmt;

use tracing_subscriber::{
    field::{RecordFields, Visit, VisitOutput},
    fmt::{
        FormattedFields,
        format::{DefaultVisitor, FormatFields, Writer},
    },
};

const REDACTED: &str = "[REDACTED]";

#[derive(Debug, Default)]
pub struct RedactingFields;

impl<'writer> FormatFields<'writer> for RedactingFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let mut visitor = RedactingVisitor {
            inner: DefaultVisitor::new(writer, true),
        };
        fields.record(&mut visitor);
        visitor.finish()
    }

    fn add_fields(
        &self,
        current: &mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        let is_empty = current.fields.is_empty();
        if !is_empty {
            current.fields.push(' ');
        }

        let mut visitor = RedactingVisitor {
            inner: DefaultVisitor::new(current.as_writer(), is_empty),
        };
        fields.record(&mut visitor);
        visitor.finish()
    }
}

struct RedactingVisitor<'writer> {
    inner: DefaultVisitor<'writer>,
}

impl Visit for RedactingVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if is_sensitive_field(field.name()) {
            self.inner.record_debug(field, &REDACTED);
        } else {
            self.inner.record_debug(field, value);
        }
    }
}

impl VisitOutput<fmt::Result> for RedactingVisitor<'_> {
    fn finish(self) -> fmt::Result {
        self.inner.finish()
    }
}

fn is_sensitive_field(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("token")
        || name.eq_ignore_ascii_case("access_token")
        || name.eq_ignore_ascii_case("bearer")
}

#[cfg(test)]
mod tests {
    use super::RedactingFields;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn sensitive_fields_are_redacted() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .fmt_fields(RedactingFields)
            .with_ansi(false)
            .with_writer({
                let output = Arc::clone(&output);
                move || SharedWriter(Arc::clone(&output))
            })
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::debug_span!(
                "authenticate",
                token = "bearer-token",
                authorization = "Bearer bearer-token",
                request_id = "safe-value"
            );
            let _entered = span.enter();
            tracing::debug!("request received");
        });

        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("bearer-token"));
        assert!(output.contains("token=\"[REDACTED]\""));
        assert!(output.contains("authorization=\"[REDACTED]\""));
        assert!(output.contains("request_id=\"safe-value\""));
    }
}
