use crate::io::BufMutExt;
use crate::message::{FrontendMessage, FrontendMessageFormat};
use sqlx_core::Error;
use std::num::Saturating;

pub struct SaslInitialResponse<'a> {
    pub mechanism: &'a str,
    pub response: &'a str,
}

impl FrontendMessage for SaslInitialResponse<'_> {
    const FORMAT: FrontendMessageFormat = FrontendMessageFormat::PasswordPolymorphic;

    #[inline(always)]
    fn body_size_hint(&self) -> Saturating<usize> {
        let mut size = Saturating(0);

        size += self.mechanism.len();
        size += 1; // NUL terminator

        size += 4; // response_len
        size += self.response.len();

        size
    }

    fn encode_body(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        // name of the SASL authentication mechanism that the client selected
        buf.put_str_nul(self.mechanism);

        let response_len = i32::try_from(self.response.len()).map_err(|_| {
            err_protocol!(
                "SASL Initial Response length too long for protocol: {}",
                self.response.len()
            )
        })?;

        buf.extend_from_slice(&response_len.to_be_bytes());
        buf.extend_from_slice(self.response.as_bytes());

        Ok(())
    }
}

pub struct SaslResponse<'a>(pub &'a str);

/// Build the OAUTHBEARER (RFC 7628) client initial response for the given bearer token.
///
/// The payload is a GS2 header followed by a single `auth=Bearer <token>`
/// attribute, as produced by PostgreSQL's `fe-auth-oauth.c`.
pub(crate) fn oauth_bearer_initial_response(token: &str) -> String {
    format!("n,,\x01auth=Bearer {token}\x01\x01")
}

impl FrontendMessage for SaslResponse<'_> {
    const FORMAT: FrontendMessageFormat = FrontendMessageFormat::PasswordPolymorphic;

    fn body_size_hint(&self) -> Saturating<usize> {
        Saturating(self.0.len())
    }

    fn encode_body(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
        buf.extend(self.0.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::FrontendMessage;

    #[test]
    fn test_oauth_bearer_initial_response() {
        assert_eq!(
            oauth_bearer_initial_response("test-token"),
            "n,,\x01auth=Bearer test-token\x01\x01",
        );
    }

    #[test]
    fn test_encode_oauth_bearer_sasl_initial_response() {
        const EXPECTED: &[u8] = b"p\x00\x00\x00\x30OAUTHBEARER\x00\x00\x00\x00\x1cn,,\x01auth=Bearer test-token\x01\x01";

        let mut buf = Vec::new();
        let m = SaslInitialResponse {
            mechanism: "OAUTHBEARER",
            response: &oauth_bearer_initial_response("test-token"),
        };

        m.encode_msg(&mut buf).unwrap();
        assert_eq!(buf, EXPECTED);
    }
}
