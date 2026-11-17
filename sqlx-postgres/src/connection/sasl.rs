use crate::connection::stream::PgStream;
use crate::error::Error;
use crate::message::{
    oauth_bearer_initial_response, Authentication, AuthenticationSasl, SaslInitialResponse,
    SaslResponse,
};
use crate::rt;
use crate::PgConnectOptions;
use hmac::{Hmac, Mac};
use hmac::{HmacReset, KeyInit};
use sha2::{Digest, Sha256};
use stringprep::saslprep;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use rand::RngExt;

const GS2_HEADER: &str = "n,,";
const CHANNEL_ATTR: &str = "c";
const USERNAME_ATTR: &str = "n";
const CLIENT_PROOF_ATTR: &str = "p";
const NONCE_ATTR: &str = "r";

pub(crate) async fn authenticate(
    stream: &mut PgStream,
    options: &PgConnectOptions,
    data: AuthenticationSasl,
) -> Result<(), Error> {
    let mut has_sasl = false;
    let mut has_sasl_plus = false;
    let mut has_oauthbearer = false;
    let mut unknown = Vec::new();

    for mechanism in data.mechanisms() {
        match mechanism {
            "SCRAM-SHA-256" => {
                has_sasl = true;
            }

            "SCRAM-SHA-256-PLUS" => {
                has_sasl_plus = true;
            }

            "OAUTHBEARER" => {
                has_oauthbearer = true;
            }

            _ => {
                unknown.push(mechanism.to_owned());
            }
        }
    }

    // OAUTHBEARER takes precedence over SCRAM so that the token supplied by
    // the user is actually used for the connection (i.e. the token can be
    // used to drive SSO-style authentication instead of a password).
    if has_oauthbearer {
        if let Some(provider) = options.oauth_token_provider.as_ref() {
            let token = provider().await.map_err(|error| {
                Error::Protocol(format!("failed to acquire OAUTHBEARER token: {error}"))
            })?;

            return authenticate_oauthbearer(stream, &token).await;
        }
    }

    if !has_sasl_plus && !has_sasl {
        if has_oauthbearer {
            return Err(err_protocol!(
                "the server requires OAUTHBEARER SASL authentication but no OAuth token was provided; \
                set `PgConnectOptions::oauth_token()` or `PgConnectOptions::oauth_token_provider()`"
            ));
        }

        return Err(err_protocol!(
            "unsupported SASL authentication mechanisms: {}",
            unknown.join(", ")
        ));
    }

    // channel-binding = "c=" base64
    let mut channel_binding = format!("{CHANNEL_ATTR}=");
    BASE64_STANDARD.encode_string(GS2_HEADER, &mut channel_binding);

    // "n=" saslname ;; Usernames are prepared using SASLprep.
    let username = format!("{}={}", USERNAME_ATTR, options.username);
    let username = match saslprep(&username) {
        Ok(v) => v,
        Err(error) => {
            return Err(Error::Configuration(
                format!("Failed to saslprep username: {:?}", error).into(),
            ))
        }
    };

    // nonce = "r=" c-nonce [s-nonce] ;; Second part provided by server.
    let nonce = gen_nonce();

    // client-first-message-bare = [reserved-mext ","] username "," nonce ["," extensions]
    let client_first_message_bare = format!("{username},{nonce}");

    let client_first_message = format!("{GS2_HEADER}{client_first_message_bare}");

    stream
        .send(SaslInitialResponse {
            // Note: channel binding (-PLUS) is not implemented; we always
            // negotiate the base mechanism, even if only the PLUS variant was offered.
            mechanism: "SCRAM-SHA-256",
            response: &client_first_message,
        })
        .await?;

    let cont = match stream.recv_expect().await? {
        Authentication::SaslContinue(data) => data,

        auth => {
            return Err(err_protocol!(
                "expected SASLContinue but received {:?}",
                auth
            ));
        }
    };

    // Normalize(password):
    let password = options.password.as_deref().unwrap_or_default();
    let password = match saslprep(password) {
        Ok(v) => v,
        Err(error) => {
            return Err(Error::Configuration(
                format!("Failed to saslprep password: {:?}", error).into(),
            ))
        }
    };

    // SaltedPassword := Hi(Normalize(password), salt, i)
    let salted_password = hi(&password, &cont.salt, cont.iterations).await?;

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    let mut mac = Hmac::<Sha256>::new_from_slice(&salted_password).map_err(Error::protocol)?;
    mac.update(b"Client Key");

    let client_key = mac.finalize().into_bytes();

    // StoredKey := H(ClientKey)
    let stored_key = Sha256::digest(client_key);

    // client-final-message-without-proof
    let client_final_message_wo_proof = format!(
        "{channel_binding},r={nonce}",
        channel_binding = channel_binding,
        nonce = &cont.nonce
    );

    // AuthMessage := client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
    let auth_message = format!(
        "{client_first_message_bare},{server_first_message},{client_final_message_wo_proof}",
        client_first_message_bare = client_first_message_bare,
        server_first_message = cont.message,
        client_final_message_wo_proof = client_final_message_wo_proof
    );

    // ClientSignature := HMAC(StoredKey, AuthMessage)
    let mut mac = Hmac::<Sha256>::new_from_slice(&stored_key).map_err(Error::protocol)?;
    mac.update(auth_message.as_bytes());

    let client_signature = mac.finalize().into_bytes();

    // ClientProof := ClientKey XOR ClientSignature
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(&a, &b)| a ^ b)
        .collect();

    // ServerKey := HMAC(SaltedPassword, "Server Key")
    let mut mac = Hmac::<Sha256>::new_from_slice(&salted_password).map_err(Error::protocol)?;
    mac.update(b"Server Key");

    let server_key = mac.finalize().into_bytes();

    // ServerSignature := HMAC(ServerKey, AuthMessage)
    let mut mac = Hmac::<Sha256>::new_from_slice(&server_key).map_err(Error::protocol)?;
    mac.update(auth_message.as_bytes());

    // client-final-message = client-final-message-without-proof "," proof
    let mut client_final_message = format!("{client_final_message_wo_proof},{CLIENT_PROOF_ATTR}=");
    BASE64_STANDARD.encode_string(client_proof, &mut client_final_message);

    stream.send(SaslResponse(&client_final_message)).await?;

    let data = match stream.recv_expect().await? {
        Authentication::SaslFinal(data) => data,

        auth => {
            return Err(err_protocol!("expected SASLFinal but received {:?}", auth));
        }
    };

    // authentication is only considered valid if this verification passes
    mac.verify_slice(&data.verifier).map_err(Error::protocol)?;

    Ok(())
}

/// Authenticate with the SASL OAUTHBEARER mechanism (RFC 7628) using a bearer
/// token supplied by the user.
///
/// This implements the single-shot variant of the exchange where the client
/// sends the token in the initial response and the server either accepts the
/// connection or fails it. The server may also respond with an error challenge
/// (an `AuthenticationSaslContinue` containing a JSON document with e.g. the
/// `status`, `scope` and `openid-configuration` fields) instead of failing
/// immediately. In that case we send the single `\x01` byte that RFC 7628
/// requires as the client's reply to the challenge and then let the server's
/// error response surface as the usual `Error::Database`.
async fn authenticate_oauthbearer(stream: &mut PgStream, token: &str) -> Result<(), Error> {
    // The response is a GS2 header followed by a single `auth=Bearer <token>`
    // key-value pair. See RFC 7628 §3.1 and PostgreSQL's `fe-auth-oauth.c`.
    let response = oauth_bearer_initial_response(token);

    stream
        .send(SaslInitialResponse {
            mechanism: "OAUTHBEARER",
            response: &response,
        })
        .await?;

    match stream.recv_expect().await? {
        // Fast path: the server accepted the token and completed the exchange
        // without sending any further SASL data. Per RFC 7628 the server
        // may omit the final `AuthenticationSaslFinal` message entirely;
        // the usual `AuthenticationOk` message follows.
        Authentication::Ok => Ok(()),

        // The server sends an `AuthenticationSaslContinue` message containing
        // a JSON error document describing the failure. Per RFC 7628 §3.2.2,
        // reply with a single `%x01` byte to complete the exchange; the server
        // then sends an ErrorResponse which surfaces as `Error::Database`.
        Authentication::SaslContinue(_) => {
            stream.send(SaslResponse("\x01")).await?;

            // the server will now send an `ErrorResponse` (or, in theory,
            // `AuthenticationOk`); `recv_expect()` will translate a fatal error
            // into `Error::Database` and anything else into an `err_protocol!`.
            match stream.recv_expect().await? {
                Authentication::Ok => Ok(()),
                auth => Err(err_protocol!(
                    "unexpected message after OAUTHBEARER error challenge: {:?}",
                    auth
                )),
            }
        }

        Authentication::SaslFinal(_) => Err(err_protocol!(
            "unexpected AuthenticationSaslFinal from OAUTHBEARER exchange \
            (PostgreSQL does not send one); token was not verified"
        )),

        auth => Err(err_protocol!(
            "expected AuthenticationOk from OAUTHBEARER exchange, received {:?}",
            auth
        )),
    }
}

// nonce is a sequence of random printable bytes
fn gen_nonce() -> String {
    let mut rng = rand::rng();
    let count = rng.random_range(64..128);

    // printable = %x21-2B / %x2D-7E
    // ;; Printable ASCII except ",".
    // ;; Note that any "printable" is also
    // ;; a valid "value".
    let nonce: String = std::iter::repeat(())
        .map(|()| {
            let mut c = rng.random_range(0x21u8..0x7F);

            while c == 0x2C {
                c = rng.random_range(0x21u8..0x7F);
            }

            c
        })
        .take(count)
        .map(|c| c as char)
        .collect();

    format!("{NONCE_ATTR}={nonce}")
}

// Hi(str, salt, i):
async fn hi<'a>(s: &'a str, salt: &'a [u8], iter_count: u32) -> Result<[u8; 32], Error> {
    let mut mac = HmacReset::<Sha256>::new_from_slice(s.as_bytes()).map_err(Error::protocol)?;

    mac.update(salt);
    mac.update(&1u32.to_be_bytes());

    let mut u = mac.finalize_reset().into_bytes();
    let mut hi = u;

    for i in 1..iter_count {
        mac.update(u.as_slice());
        u = mac.finalize_reset().into_bytes();
        hi = hi.iter().zip(u.iter()).map(|(&a, &b)| a ^ b).collect();

        // For large iteration counts, this process can take a long time and block the event loop.
        // It was measured as taking ~50ms for 4096 iterations (the default) on a developer machine.
        // If we want to yield every 10-100us (as generally advised for tokio), then we can yield
        // every 5 iterations which should be every ~50us.
        if i % 5 == 0 {
            rt::yield_now().await;
        }
    }

    Ok(hi.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::stream::PgStream;
    use crate::message::{Authentication, BackendMessage};
    use crate::net::Socket;
    use sqlx_core::io::ReadBuf;

    use std::collections::VecDeque;
    use std::io;
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    /// A mock socket that replays a scripted sequence of bytes from the server
    /// and captures everything the client writes.
    struct MockSocket {
        read: VecDeque<u8>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Socket for MockSocket {
        fn try_read(&mut self, buf: &mut dyn ReadBuf) -> io::Result<usize> {
            if self.read.is_empty() {
                return Ok(0); // EOF
            }

            let mut n = 0;
            while let Some(byte) = self.read.pop_front() {
                if n >= buf.remaining_mut() {
                    self.read.push_front(byte);
                    break;
                }
                buf.put_u8(byte);
                n += 1;
            }

            Ok(n)
        }

        fn try_write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn poll_read_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_write_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Polls a future that is guaranteed to complete immediately on its first poll.
    fn poll_immediate<F: std::future::Future>(fut: F) -> F::Output {
        let mut fut = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => val,
            Poll::Pending => panic!("test future was pending unexpectedly"),
        }
    }

    /// Serialize a backend message: `tag`, then the 4-byte BE length (including
    /// the length bytes themselves), then `body`.
    fn backend_message(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(5 + body.len());
        msg.push(tag);
        msg.extend_from_slice(&((body.len() as u32 + 4).to_be_bytes()));
        msg.extend_from_slice(body);
        msg
    }

    fn authentication_ok() -> Vec<u8> {
        backend_message(b'R', &0u32.to_be_bytes())
    }

    fn authentication_sasl_continue_json(json: &str) -> Vec<u8> {
        let mut body = 11u32.to_be_bytes().to_vec();
        body.extend_from_slice(json.as_bytes());
        backend_message(b'R', &body)
    }

    fn error_response_invalid_authorization() -> Vec<u8> {
        // FATAL, SQLSTATE 28000 (invalid_authorization_specification)
        let mut body = Vec::new();
        for (field, value) in [
            (b'S', &b"FATAL"[..]),
            (b'V', &b"FATAL"[..]),
            (b'C', &b"28000"[..]),
            (
                b'M',
                &b"OAuth bearer authentication failed for user \"postgres\""[..],
            ),
        ] {
            body.push(field);
            body.extend_from_slice(value);
            body.push(0);
        }
        body.push(0);
        backend_message(b'E', &body)
    }

    fn oauthbearer_sasl() -> AuthenticationSasl {
        match Authentication::decode_body(sqlx_core::bytes::Bytes::from_static(
            b"\0\0\0\x0aOAUTHBEARER\0\0",
        ))
        .unwrap()
        {
            Authentication::Sasl(sasl) => sasl,
            other => panic!("expected Authentication::Sasl, got {:?}", other),
        }
    }

    /// Build a [`PgConnectOptions`] with the given OAuth token configured.
    fn options_with_token(token: &str) -> PgConnectOptions {
        PgConnectOptions::new().oauth_token(token)
    }

    #[test]
    fn oauthbearer_success() {
        poll_immediate(async {
            let server_bytes = authentication_ok();

            let written = Arc::new(Mutex::new(Vec::new()));
            let socket = MockSocket {
                read: server_bytes.into_iter().collect(),
                written: written.clone(),
            };

            let options = options_with_token("test-token");
            let sasl = oauthbearer_sasl();

            let mut stream = PgStream::new_for_test(Box::new(socket));
            authenticate(&mut stream, &options, sasl).await.unwrap();

            let written = written.lock().unwrap();
            let written = String::from_utf8_lossy(&written);
            assert!(written.starts_with('p'));
            assert!(written.contains("OAUTHBEARER\0"));
            assert!(written.contains("n,,\x01auth=Bearer test-token\x01\x01"));
        });
    }

    #[test]
    fn oauthbearer_invalid_token_challenge() {
        poll_immediate(async {
            let error_json = r#"{"status":"invalid_token","scope":"openid","openid-configuration":"https://issuer.example.com/.well-known/openid-configuration"}"#;

            let mut server_bytes = authentication_sasl_continue_json(error_json);
            server_bytes.extend(error_response_invalid_authorization());

            let written = Arc::new(Mutex::new(Vec::new()));
            let socket = MockSocket {
                read: server_bytes.into_iter().collect(),
                written: written.clone(),
            };

            let options = options_with_token("bad-token");
            let sasl = oauthbearer_sasl();

            let mut stream = PgStream::new_for_test(Box::new(socket));
            let err = authenticate(&mut stream, &options, sasl).await.unwrap_err();

            // the server sends an ErrorResponse, which surfaces as a database error
            let db_err = err.as_database_error().expect("expected a database error");
            assert_eq!(db_err.code().as_deref(), Some("28000"));

            // the client must have replied with the single %x01 byte
            let written = written.lock().unwrap();
            let reply = &written[written.len() - 6..];
            assert_eq!(reply, b"p\0\0\0\x05\x01");
        });
    }

    #[test]
    fn oauthbearer_no_token_configured() {
        poll_immediate(async {
            let server_bytes = Vec::new();
            let written = Arc::new(Mutex::new(Vec::new()));
            let socket = MockSocket {
                read: server_bytes.into_iter().collect(),
                written,
            };

            let options = PgConnectOptions::new();
            let sasl = oauthbearer_sasl();

            let mut stream = PgStream::new_for_test(Box::new(socket));
            let err = authenticate(&mut stream, &options, sasl).await.unwrap_err();
            assert!(err.to_string().contains("OAUTHBEARER"));
        });
    }
}
