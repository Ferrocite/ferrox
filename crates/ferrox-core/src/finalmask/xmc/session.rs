use super::cfb8::Cfb8;
use super::packet_stream::PacketStream;
use super::padding::run_stream;
use super::padding_preset::{new_client_schedule, new_server_schedule};
use super::profile::{find_profile, profiles_from_config, read_login_success, Profile};
use super::protocol::{
    read_bytes, read_packet, read_packet_with_length, read_string, read_unsigned_short, read_uuid,
    read_varint, write_boolean, write_bytes, write_packet, write_packet_with_length, write_string,
    write_unsigned_short, write_uuid, write_varint,
};
use boring::pkey::PKey;
use boring::rsa::{Padding, Rsa};
use std::io::{self, Read, Write};
use std::net::SocketAddr;

const PROTOCOL_VERSION: i32 = 775;
const DEFAULT_PORT: u16 = 25565;
const LOGIN_STATE: i32 = 2;
const STATUS_STATE: i32 = 1;
const STATUS_RESPONSE: &str =
    "{\"description\":\"A Minecraft Server\",\"players\":{\"max\":20,\"online\":0},\"version\":{\"name\":\"26.1.2\",\"protocol\":775},\"enforcesSecureChat\":true}";
const AUTH_FAILURE: &str =
    "{\"type\":\"translatable\",\"translate\":\"multiplayer.disconnect.authservers_down\"}";
const NOT_WHITELISTED: &str = "{\"text\":\"You are not white-listed on this server!\"}";

#[derive(Clone)]
pub struct Config {
    pub profiles: Vec<Profile>,
    pub password: String,
    pub hostname: String,
    pub private_key_der: Vec<u8>,
    pub public_key_der: Vec<u8>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("xmc::Config")
            .field("profiles", &self.profiles.len())
            .field("hostname", &self.hostname)
            .field("password", &self.password.len())
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn new(
        profiles: Vec<Profile>,
        password: String,
        hostname: String,
        private_key_der: Vec<u8>,
        public_key_der: Vec<u8>,
    ) -> io::Result<Self> {
        profiles_from_config(&profiles)?;
        if password.is_empty() {
            return Err(invalid_input("xmc: empty password"));
        }
        if private_key_der.is_empty() || public_key_der.is_empty() {
            return Err(invalid_input("xmc: empty key"));
        }
        Ok(Self {
            profiles,
            password,
            hostname,
            private_key_der,
            public_key_der,
        })
    }
}

pub struct Session<R, W> {
    packet: PacketStream<CipherReader<R>, CipherWriter<W>>,
}

impl<R, W> std::fmt::Debug for Session<R, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("xmc::Session")
            .finish_non_exhaustive()
    }
}

impl<R: Read, W: Write + Send + 'static> Session<R, W> {
    pub fn client(
        reader: R,
        writer: W,
        config: &Config,
        remote: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let profiles = profiles_from_config(&config.profiles)?;
        let public_key = public_key(config)?;
        let profile = random_profile(&profiles)?;
        let mut stream = Handshake::new(reader, writer);
        let (address, port) = match remote {
            Some(remote) if config.hostname.is_empty() => (remote.ip().to_string(), remote.port()),
            Some(remote) => (config.hostname.clone(), remote.port()),
            None => (config.hostname.clone(), DEFAULT_PORT),
        };

        let mut data = Vec::new();
        write_varint(&mut data, PROTOCOL_VERSION)?;
        write_string(&mut data, &address)?;
        write_unsigned_short(&mut data, port)?;
        write_varint(&mut data, LOGIN_STATE)?;
        write_packet(&mut stream, 0x00, &data)?;

        let mut data = Vec::new();
        write_string(&mut data, &profile.username)?;
        write_uuid(&mut data, &profile.uuid)?;
        write_packet(&mut stream, 0x00, &data)?;

        let packet = read_packet(&mut stream)?;
        if packet.id != 0x01 {
            return Err(invalid_data("xmc: unexpected login packet"));
        }
        let mut body = packet.data.as_slice();
        read_string(&mut body)?;
        let server_key = read_bytes(&mut body)?;
        let token = read_bytes(&mut body)?;
        if server_key != config.public_key_der {
            return Err(invalid_data("xmc: server key mismatch"));
        }
        let mut secret = [0u8; 16];
        getrandom::fill(&mut secret).map_err(|_| io::Error::other("xmc: no entropy"))?;
        let encrypted_secret = encrypt(&public_key, &secret)?;
        let mut token_and_password = token;
        token_and_password.extend_from_slice(config.password.as_bytes());
        let encrypted_token = encrypt(&public_key, &token_and_password)?;

        let mut data = Vec::new();
        write_bytes(&mut data, &encrypted_secret)?;
        write_bytes(&mut data, &encrypted_token)?;
        write_packet(&mut stream, 0x01, &data)?;
        stream.enable_cipher(&secret);

        let packet = read_packet(&mut stream)?;
        match packet.id {
            0x00 => {
                let mut body = packet.data.as_slice();
                let reason = read_string(&mut body)?;
                return Err(io::Error::other(format!("xmc: disconnected: {reason}")));
            }
            0x02 => {
                if read_login_success(&packet)? != profile {
                    return Err(invalid_data("xmc: profile mismatch"));
                }
            }
            _ => return Err(invalid_data("xmc: unexpected login result")),
        }

        let first_prefix = write_packet_with_length(&mut stream, 0x03, &[])?;
        let schedule = new_client_schedule()?;
        run_stream(&mut stream, true, i64_len(first_prefix), &schedule)?;
        let (reader, writer) = stream.into_cipherstream()?;
        Ok(Self {
            packet: PacketStream::new(reader, writer, true),
        })
    }

    pub fn server(reader: R, writer: W, config: &Config) -> io::Result<Self> {
        let profiles = profiles_from_config(&config.profiles)?;
        let private_key = Rsa::private_key_from_der(&config.private_key_der)
            .map_err(|error| invalid_data(format!("xmc: private key: {error}")))?;
        let mut stream = Handshake::new(reader, writer);
        let packet = read_packet(&mut stream)?;
        if packet.id != 0x00 {
            return Err(invalid_data("xmc: unexpected handshake"));
        }
        let mut body = packet.data.as_slice();
        read_varint(&mut body)?;
        read_string(&mut body)?;
        read_unsigned_short(&mut body)?;
        let next_state = read_varint(&mut body)?;

        if next_state == STATUS_STATE {
            return Err(status(&mut stream));
        }
        if next_state != LOGIN_STATE {
            return Err(invalid_data("xmc: unsupported next state"));
        }

        let packet = read_packet(&mut stream)?;
        if packet.id != 0x00 {
            return Err(invalid_data("xmc: unexpected login start"));
        }
        let mut body = packet.data.as_slice();
        let username = read_string(&mut body)?;
        let uuid = read_uuid(&mut body)?;
        let profile = find_profile(&profiles, &username, &uuid).cloned();

        let mut token = [0u8; 4];
        getrandom::fill(&mut token).map_err(|_| io::Error::other("xmc: no entropy"))?;
        let mut data = Vec::new();
        write_string(&mut data, "")?;
        write_bytes(&mut data, &config.public_key_der)?;
        write_bytes(&mut data, &token)?;
        write_boolean(&mut data, true)?;
        write_packet(&mut stream, 0x01, &data)?;

        let packet = read_packet(&mut stream)?;
        if packet.id != 0x01 {
            return Err(invalid_data("xmc: unexpected encryption response"));
        }
        let mut body = packet.data.as_slice();
        let encrypted_secret = read_bytes(&mut body)?;
        let encrypted_token = read_bytes(&mut body)?;
        let secret = decrypt(&private_key, &encrypted_secret)?;
        let token_and_password = decrypt(&private_key, &encrypted_token)?;
        let secret: [u8; 16] = secret
            .try_into()
            .map_err(|_| invalid_data("xmc: bad shared secret"))?;
        if token_and_password.len() < token.len() || token_and_password[..4] != token {
            return Err(invalid_data("xmc: bad token"));
        }
        stream.enable_cipher(&secret);

        if !constant_time_eq(&token_and_password[4..], config.password.as_bytes()) {
            write_disconnect(&mut stream, AUTH_FAILURE)?;
            return Err(invalid_data("xmc: bad password"));
        }
        let Some(profile) = profile else {
            write_disconnect(&mut stream, NOT_WHITELISTED)?;
            return Err(invalid_data("xmc: unknown profile"));
        };

        let mut data = Vec::new();
        write_uuid(&mut data, &profile.uuid)?;
        write_string(&mut data, &profile.username)?;
        write_varint(&mut data, 1)?;
        write_string(&mut data, "textures")?;
        write_string(&mut data, &profile.textures_value)?;
        write_boolean(&mut data, true)?;
        write_string(&mut data, &profile.textures_signature)?;
        write_packet(&mut stream, 0x02, &data)?;

        let (packet, first_prefix) = read_packet_with_length(&mut stream)?;
        if packet.id != 0x03 || !packet.data.is_empty() {
            return Err(invalid_data("xmc: login was not acknowledged"));
        }
        let schedule = new_server_schedule()?;
        run_stream(&mut stream, false, i64_len(first_prefix), &schedule)?;
        let (reader, writer) = stream.into_cipherstream()?;
        Ok(Self {
            packet: PacketStream::new(reader, writer, false),
        })
    }
}

impl<R, W> Read for Session<R, W>
where
    R: Read,
    W: Write,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        (&self.packet).read(output)
    }
}

impl<R, W> Write for Session<R, W>
where
    R: Read,
    W: Write,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        (&self.packet).write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.packet).flush()
    }
}

impl<R, W> Read for &Session<R, W>
where
    R: Read,
    W: Write,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        (&self.packet).read(output)
    }
}

impl<R, W> Write for &Session<R, W>
where
    R: Read,
    W: Write,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        (&self.packet).write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.packet).flush()
    }
}

impl<R, W> Session<R, W>
where
    W: Write,
{
    pub fn stop(&self) {
        self.packet.stop();
    }
}

struct Handshake<R, W> {
    reader: R,
    writer: W,
    read_cipher: Option<Cfb8>,
    write_cipher: Option<Cfb8>,
    buffer: Vec<u8>,
}

impl<R, W> Handshake<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            read_cipher: None,
            write_cipher: None,
            buffer: Vec::new(),
        }
    }

    fn enable_cipher(&mut self, secret: &[u8; 16]) {
        self.read_cipher = Some(Cfb8::decrypt(secret));
        self.write_cipher = Some(Cfb8::encrypt(secret));
    }

    fn into_cipherstream(self) -> io::Result<(CipherReader<R>, CipherWriter<W>)> {
        let read_cipher = self
            .read_cipher
            .ok_or_else(|| invalid_data("xmc: read cipher not armed"))?;
        let write_cipher = self
            .write_cipher
            .ok_or_else(|| invalid_data("xmc: write cipher not armed"))?;
        Ok((
            CipherReader {
                reader: self.reader,
                cipher: read_cipher,
            },
            CipherWriter {
                writer: self.writer,
                cipher: write_cipher,
                buffer: Vec::new(),
            },
        ))
    }
}

impl<R: Read, W> Read for Handshake<R, W> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.reader.read(output)?;
        if let Some(cipher) = &mut self.read_cipher {
            cipher.apply(&mut output[..read]);
        }
        Ok(read)
    }
}

impl<R, W: Write> Write for Handshake<R, W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if let Some(cipher) = &mut self.write_cipher {
            self.buffer.clear();
            self.buffer.extend_from_slice(input);
            cipher.apply(&mut self.buffer);
            self.writer.write_all(&self.buffer)?;
        } else {
            self.writer.write_all(input)?;
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct CipherReader<R> {
    reader: R,
    cipher: Cfb8,
}

impl<R: Read> Read for CipherReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.reader.read(output)?;
        self.cipher.apply(&mut output[..read]);
        Ok(read)
    }
}

struct CipherWriter<W> {
    writer: W,
    cipher: Cfb8,
    buffer: Vec<u8>,
}

impl<W: Write> Write for CipherWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.buffer.clear();
        self.buffer.extend_from_slice(input);
        self.cipher.apply(&mut self.buffer);
        self.writer.write_all(&self.buffer)?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn public_key(config: &Config) -> io::Result<Rsa<boring::pkey::Public>> {
    PKey::public_key_from_der(&config.public_key_der)
        .and_then(|key| key.rsa())
        .map_err(|error| invalid_data(format!("xmc: public key: {error}")))
}

fn encrypt(key: &Rsa<boring::pkey::Public>, plain: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = vec![0; key.size() as usize];
    let length = key
        .public_encrypt(plain, &mut output, Padding::PKCS1)
        .map_err(|error| io::Error::other(format!("xmc: encrypt: {error}")))?;
    output.truncate(length);
    Ok(output)
}

fn decrypt(key: &Rsa<boring::pkey::Private>, cipher: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = vec![0; key.size() as usize];
    let length = key
        .private_decrypt(cipher, &mut output, Padding::PKCS1)
        .map_err(|error| io::Error::other(format!("xmc: decrypt: {error}")))?;
    output.truncate(length);
    Ok(output)
}

fn random_profile(profiles: &[Profile]) -> io::Result<Profile> {
    let mut draw = [0u8; 8];
    getrandom::fill(&mut draw).map_err(|_| io::Error::other("xmc: no entropy"))?;
    let index = u64::from_le_bytes(draw) as usize % profiles.len();
    Ok(profiles[index].clone())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn status<R: Read, W: Write>(stream: &mut Handshake<R, W>) -> io::Error {
    for _ in 0..2 {
        let Ok(packet) = read_packet(stream) else {
            break;
        };
        let result = match packet.id {
            0x00 => {
                let mut data = Vec::new();
                let _ = write_string(&mut data, STATUS_RESPONSE);
                write_packet(stream, 0x00, &data)
            }
            0x01 => write_packet(stream, 0x01, &packet.data),
            _ => Ok(()),
        };
        if result.is_err() {
            break;
        }
    }
    invalid_data("xmc: status session closed")
}

fn write_disconnect<R: Read, W: Write>(
    stream: &mut Handshake<R, W>,
    reason: &str,
) -> io::Result<()> {
    let mut data = Vec::new();
    write_string(&mut data, reason)?;
    write_packet(stream, 0x00, &data)
}

fn i64_len(length: usize) -> i64 {
    i64::try_from(length).unwrap_or(i64::MAX)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xmc::derivation::{derive_rsa_key, private_key_der, public_key_der};
    use std::collections::VecDeque;
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;

    #[derive(Clone)]
    struct Pipe {
        bytes: Arc<(Mutex<VecDeque<u8>>, Condvar)>,
    }

    impl Pipe {
        fn new() -> Self {
            Self {
                bytes: Arc::new((Mutex::new(VecDeque::new()), Condvar::new())),
            }
        }
    }

    impl Read for Pipe {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let (lock, ready) = &*self.bytes;
            let mut bytes = lock.lock().expect("pipe");
            while bytes.is_empty() {
                bytes = ready.wait(bytes).expect("pipe");
            }
            let taken = output.len().min(bytes.len());
            for (slot, byte) in output.iter_mut().zip(bytes.drain(..taken)) {
                *slot = byte;
            }
            Ok(taken)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            let (lock, ready) = &*self.bytes;
            lock.lock().expect("pipe").extend(input);
            ready.notify_all();
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn profile(username: &str) -> Profile {
        Profile {
            username: username.to_owned(),
            uuid: [0x33; 16],
            textures_value: "textures-value".to_owned(),
            textures_signature: "textures-signature".to_owned(),
        }
    }

    fn config(profiles: Vec<Profile>) -> Config {
        let password = "shared-password";
        let key = derive_rsa_key(password).expect("key");
        Config::new(
            profiles,
            password.to_owned(),
            "example.test".to_owned(),
            private_key_der(&key).expect("private"),
            public_key_der(&key).expect("public"),
        )
        .expect("config")
    }

    fn pair() -> (Pipe, Pipe) {
        (Pipe::new(), Pipe::new())
    }

    #[test]
    fn a_paired_handshake_carries_both_directions() {
        let (client_to_server, server_to_client) = pair();
        let server_config = config(vec![profile("SignedUser")]);
        let client_config = server_config.clone();
        let (server_reader, server_writer) = (client_to_server.clone(), server_to_client.clone());
        let server = thread::spawn(move || {
            let mut session =
                Session::server(server_reader, server_writer, &server_config).expect("server");
            let mut received = [0; 5];
            session.read_exact(&mut received).expect("server reads");
            assert_eq!(&received, b"hello");
            session.write_all(b"world").expect("server writes");
        });

        let mut client = Session::client(server_to_client, client_to_server, &client_config, None)
            .expect("client");
        client.write_all(b"hello").expect("client writes");
        let mut received = [0; 5];
        client.read_exact(&mut received).expect("client reads");
        assert_eq!(&received, b"world");
        server.join().expect("server thread");
    }

    #[test]
    fn an_unknown_profile_is_disconnected() {
        let (client_to_server, server_to_client) = pair();
        let server_config = config(vec![profile("KnownUser")]);
        let client_config = config(vec![profile("OtherUser")]);
        assert_eq!(server_config.public_key_der, client_config.public_key_der);
        let (server_reader, server_writer) = (client_to_server.clone(), server_to_client.clone());
        let server = thread::spawn(move || {
            Session::server(server_reader, server_writer, &server_config)
                .expect_err("unknown profile")
        });

        let Err(error) = Session::client(server_to_client, client_to_server, &client_config, None)
        else {
            panic!("client accepted a disconnect");
        };
        assert!(error.to_string().contains("disconnected"), "{error}");
        let server_error = server.join().expect("server thread");
        assert!(
            server_error.to_string().contains("unknown profile"),
            "{server_error}"
        );
    }
}
