#[cfg(test)]
use super::protocol::write_long;
use super::protocol::{read_long, read_packet, read_string, write_packet, write_string, Packet};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const CHANNEL: &str = "xmc:data";
pub const CLIENTBOUND_CUSTOM_PAYLOAD: i32 = 0x01;
pub const SERVERBOUND_CUSTOM_PAYLOAD: i32 = 0x02;
pub const KEEPALIVE_PACKET: i32 = 0x04;
pub const MAX_PACKET_DATA: usize = 24 * 1024;
pub const KEEPALIVE_PERIOD: Duration = Duration::from_secs(15);

const KEEPALIVE_POLL: Duration = Duration::from_millis(100);
const KEEPALIVE_POLLS: usize = 150;

pub struct PacketStream<R, W> {
    reader: R,
    writer: Arc<Mutex<W>>,
    is_client: bool,
    pending: Vec<u8>,
    stop: Arc<AtomicBool>,
    keepalive: Option<JoinHandle<()>>,
}

impl<R, W> PacketStream<R, W>
where
    W: Write + Send + 'static,
{
    pub fn new(reader: R, writer: W, is_client: bool) -> Self {
        let writer = Arc::new(Mutex::new(writer));
        let stop = Arc::new(AtomicBool::new(false));
        let keepalive = if is_client {
            None
        } else {
            Some(spawn_keepalive(Arc::clone(&writer), Arc::clone(&stop)))
        };
        Self {
            reader,
            writer,
            is_client,
            pending: Vec::new(),
            stop,
            keepalive,
        }
    }
}

impl<R, W: Write> PacketStream<R, W> {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn shutdown(&mut self) {
        self.stop();
        if let Some(handle) = self.keepalive.take() {
            let _ = handle.join();
        }
    }

    fn local_custom_payload_id(&self) -> i32 {
        if self.is_client {
            SERVERBOUND_CUSTOM_PAYLOAD
        } else {
            CLIENTBOUND_CUSTOM_PAYLOAD
        }
    }

    fn remote_custom_payload_id(&self) -> i32 {
        if self.is_client {
            CLIENTBOUND_CUSTOM_PAYLOAD
        } else {
            SERVERBOUND_CUSTOM_PAYLOAD
        }
    }

    fn write_keepalive(&self, id: i64) -> io::Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?;
        write_packet(&mut *writer, KEEPALIVE_PACKET, &id.to_be_bytes())
            .map_err(|error| io::Error::other(format!("write minecraft keep-alive: {error}")))
    }
}

impl<R: Read, W: Write> Read for PacketStream<R, W> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if !self.pending.is_empty() {
            let taken = output.len().min(self.pending.len());
            output[..taken].copy_from_slice(&self.pending[..taken]);
            self.pending.drain(..taken);
            return Ok(taken);
        }

        loop {
            let packet = read_packet(&mut self.reader).map_err(|error| {
                io::Error::other(format!("read minecraft packet stream: {error}"))
            })?;
            if packet.id == self.remote_custom_payload_id() {
                let Some(payload) = parse_custom_payload(&packet)? else {
                    continue;
                };
                if payload.is_empty() {
                    continue;
                }
                let taken = output.len().min(payload.len());
                output[..taken].copy_from_slice(&payload[..taken]);
                if taken < payload.len() {
                    self.pending.extend_from_slice(&payload[taken..]);
                }
                return Ok(taken);
            }

            if packet.id == KEEPALIVE_PACKET {
                let mut data = packet.data.as_slice();
                let id = read_long(&mut data).map_err(|error| {
                    io::Error::other(format!("read minecraft keep-alive: {error}"))
                })?;
                if self.is_client {
                    self.write_keepalive(id)?;
                }
            }
        }
    }
}

impl<R, W: Write> Write for PacketStream<R, W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?;
        let mut written = 0;
        while written < input.len() {
            let end = (written + MAX_PACKET_DATA).min(input.len());
            let mut data = Vec::with_capacity(CHANNEL.len() + end - written + 1);
            write_string(&mut data, CHANNEL)?;
            data.extend_from_slice(&input[written..end]);
            write_packet(&mut *writer, self.local_custom_payload_id(), &data).map_err(|error| {
                io::Error::other(format!("write minecraft custom payload: {error}"))
            })?;
            written = end;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer
            .lock()
            .map_err(|_| io::Error::other("packet stream writer poisoned"))?
            .flush()
    }
}

impl<R, W> Drop for PacketStream<R, W> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.keepalive.take() {
            let _ = handle.join();
        }
    }
}

impl<R, W> std::fmt::Debug for PacketStream<R, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PacketStream")
            .field("is_client", &self.is_client)
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

fn parse_custom_payload(packet: &Packet) -> io::Result<Option<Vec<u8>>> {
    let mut data = packet.data.as_slice();
    let channel = read_string(&mut data).map_err(|error| {
        io::Error::other(format!("read minecraft custom payload channel: {error}"))
    })?;
    if channel != CHANNEL {
        return Ok(None);
    }
    Ok(Some(data.to_vec()))
}

fn spawn_keepalive<W: Write + Send + 'static>(
    writer: Arc<Mutex<W>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let id = AtomicI64::new(0);
        loop {
            for _ in 0..KEEPALIVE_POLLS {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(KEEPALIVE_POLL);
            }
            let Ok(mut writer) = writer.lock() else {
                return;
            };
            let value = id.fetch_add(1, Ordering::Relaxed) + 1;
            if write_packet(&mut *writer, KEEPALIVE_PACKET, &value.to_be_bytes()).is_err() {
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalmask::xmc::protocol::{encode_packet, read_varint_with_length};
    use std::collections::VecDeque;

    #[derive(Clone)]
    struct Pipe {
        bytes: Arc<Mutex<VecDeque<u8>>>,
    }

    impl Pipe {
        fn new() -> Self {
            Self {
                bytes: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn push(&self, data: &[u8]) {
            self.bytes.lock().expect("pipe").extend(data);
        }

        fn collected(&self) -> Vec<u8> {
            self.bytes.lock().expect("pipe").drain(..).collect()
        }
    }

    impl Read for Pipe {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let mut bytes = self.bytes.lock().expect("pipe");
            let taken = output.len().min(bytes.len());
            for (slot, byte) in output.iter_mut().zip(bytes.drain(..taken)) {
                *slot = byte;
            }
            Ok(taken)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.push(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn frame(id: i32, data: &[u8]) -> Vec<u8> {
        encode_packet(id, data).expect("frame")
    }

    #[test]
    fn writes_split_at_the_payload_limit_and_round_trip_both_ways() {
        let client_out = Pipe::new();
        let server_out = Pipe::new();
        let mut client = PacketStream::new(server_out.clone(), client_out.clone(), true);
        let mut server = PacketStream::new(client_out.clone(), server_out.clone(), false);

        let client_payload: Vec<u8> = (0..60_000).map(|index| (index % 251) as u8).collect();
        let server_payload: Vec<u8> = (0..50_000).map(|index| (index % 239) as u8).collect();

        client.write_all(&client_payload).expect("client writes");
        let mut received = vec![0; client_payload.len()];
        server.read_exact(&mut received).expect("server reads");
        assert_eq!(received, client_payload);

        server.write_all(&server_payload).expect("server writes");
        let mut received = vec![0; server_payload.len()];
        client.read_exact(&mut received).expect("client reads");
        assert_eq!(received, server_payload);

        client.shutdown();
        server.shutdown();
    }

    #[test]
    fn a_write_over_the_limit_becomes_several_frames() {
        let out = Pipe::new();
        let mut stream = PacketStream::new(Pipe::new(), out.clone(), true);
        let payload = vec![7u8; MAX_PACKET_DATA * 2 + 1];
        assert_eq!(stream.write(&payload).expect("writes"), payload.len());

        let wire = out.collected();
        let mut data = wire.as_slice();
        let mut frames = 0;
        let mut recovered = Vec::new();
        while !data.is_empty() {
            let (length, prefix) = read_varint_with_length(&mut data).expect("length");
            let body = &data[..length as usize];
            data = &data[length as usize..];
            let mut body_reader = body;
            let _ = read_varint_with_length(&mut body_reader).expect("id");
            let _ = prefix;
            let payload = parse_custom_payload(&Packet {
                id: body[0] as i32,
                data: body[1..].to_vec(),
            })
            .expect("payload")
            .expect("channel");
            recovered.extend_from_slice(&payload);
            frames += 1;
        }
        assert_eq!(frames, 3);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn a_client_echoes_keepalives_and_skips_other_payloads() {
        let out = Pipe::new();
        let input = Pipe::new();

        let mut keepalive = Vec::new();
        write_long(&mut keepalive, 42).expect("keepalive");
        input.push(&frame(KEEPALIVE_PACKET, &keepalive));

        let mut foreign = Vec::new();
        write_string(&mut foreign, "minecraft:brand").expect("channel");
        foreign.extend_from_slice(b"ignored");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &foreign));

        let mut empty = Vec::new();
        write_string(&mut empty, CHANNEL).expect("channel");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &empty));

        let mut payload = Vec::new();
        write_string(&mut payload, CHANNEL).expect("channel");
        payload.extend_from_slice(b"hello");
        input.push(&frame(CLIENTBOUND_CUSTOM_PAYLOAD, &payload));

        let mut client = PacketStream::new(input, out.clone(), true);
        let mut received = [0; 5];
        client.read_exact(&mut received).expect("reads payload");
        assert_eq!(&received, b"hello");

        let echoed = out.collected();
        let mut data = echoed.as_slice();
        let (length, _) = read_varint_with_length(&mut data).expect("length");
        let body = &data[..length as usize];
        let mut body_reader = body;
        assert_eq!(
            read_varint_with_length(&mut body_reader).expect("id").0,
            KEEPALIVE_PACKET
        );
        assert_eq!(read_long(&mut body_reader).expect("id"), 42);
        assert_eq!(data.len(), length as usize, "only the keepalive is echoed");

        client.shutdown();
    }

    #[test]
    fn a_server_ignores_inbound_keepalives() {
        let out = Pipe::new();
        let input = Pipe::new();

        let mut keepalive = Vec::new();
        write_long(&mut keepalive, 7).expect("keepalive");
        input.push(&frame(KEEPALIVE_PACKET, &keepalive));

        let mut payload = Vec::new();
        write_string(&mut payload, CHANNEL).expect("channel");
        payload.extend_from_slice(b"data");
        input.push(&frame(SERVERBOUND_CUSTOM_PAYLOAD, &payload));

        let mut server = PacketStream::new(input, out.clone(), false);
        let mut received = [0; 4];
        server.read_exact(&mut received).expect("reads payload");
        assert_eq!(&received, b"data");
        assert!(out.collected().is_empty(), "a server does not echo");

        server.shutdown();
    }

    #[test]
    fn channel_frames_are_plain_minecraft_framing() {
        let out = Pipe::new();
        let mut stream = PacketStream::new(Pipe::new(), out.clone(), true);
        stream.write_all(b"hello").expect("writes");
        assert_eq!(
            out.collected(),
            [
                0x0f, 0x02, 0x08, b'x', b'm', b'c', b':', b'd', b'a', b't', b'a', b'h', b'e', b'l',
                b'l', b'o'
            ]
        );
        stream.shutdown();
    }
}
