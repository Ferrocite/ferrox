//! The `header-custom` mask: a handshake of configured byte sequences, each side answering the
//! other, followed by the stream unchanged. The reference runs the client's sequences and reads the
//! server's interleaved, so this layer sits outside the one-way stage chain and drives both chains
//! once before the first byte of the session moves.

use super::MaskRole;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The captured variables live one handshake beyond the connection that wrote them, keyed by the
/// socket pair, so a reused value survives a reconnect the way the reference's state store does.
const STATE_TTL: Duration = Duration::from_secs(5);

/// One `clients`, `servers` or `errors` entry: the items a side sends or expects in order.
#[derive(Debug, Clone, Default)]
pub struct Sequence {
    pub items: Vec<Item>,
}

/// One item of a sequence: at most one of `packet`, `rand`, `reuse` and `transform` produces bytes.
#[derive(Debug, Clone, Default)]
pub struct Item {
    pub delay: (i64, i64),
    pub rand: i32,
    pub rand_min: i32,
    pub rand_max: i32,
    pub packet: Option<Vec<u8>>,
    pub save: String,
    pub reuse: String,
    pub transform: Option<Expr>,
}

/// A configured expression: an operation and its arguments.
#[derive(Debug, Clone)]
pub struct Expr {
    pub op: String,
    pub args: Vec<ExprArg>,
}

/// One expression argument, exactly one of the variants.
#[derive(Debug, Clone)]
pub enum ExprArg {
    Bytes(Vec<u8>),
    U64(u64),
    Var(String),
    Metadata(String),
    Expr(Expr),
}

/// The three configured lists, validated as the reference's loader validates them.
#[derive(Debug, Clone, Default)]
pub struct HeaderCustom {
    clients: Vec<Sequence>,
    servers: Vec<Sequence>,
    errors: Vec<Sequence>,
    state: Arc<Mutex<StateStore>>,
}

impl HeaderCustom {
    /// A mask the config can drive: every item has at most one kind, every variable name is a Go
    /// identifier, every random bound is a byte, and every transform names an op with arguments.
    pub fn new(
        clients: Vec<Sequence>,
        servers: Vec<Sequence>,
        errors: Vec<Sequence>,
    ) -> Option<Self> {
        for sequence in clients.iter().chain(&servers).chain(&errors) {
            for item in &sequence.items {
                if !valid_var(&item.save) || !valid_var(&item.reuse) {
                    return None;
                }
                let kinds = usize::from(item.packet.is_some())
                    + usize::from(item.rand > 0)
                    + usize::from(!item.reuse.is_empty())
                    + usize::from(item.transform.is_some());
                if kinds > 1 || (kinds == 0 && !item.save.is_empty()) {
                    return None;
                }
                if !(0..=255).contains(&item.rand_min) || !(0..=255).contains(&item.rand_max) {
                    return None;
                }
                if let Some(expr) = &item.transform {
                    validate_expr(expr)?;
                }
            }
        }
        Some(Self {
            clients,
            servers,
            errors,
            state: Arc::default(),
        })
    }

    /// One connection's handshake state; every connection starts with its own captured variables.
    pub fn open(
        &self,
        role: MaskRole,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        now: Duration,
    ) -> HeaderRun {
        let vars = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.get(local, remote, now))
            .unwrap_or_default();
        HeaderRun {
            role,
            local,
            remote,
            done: false,
            failed: false,
            vars,
            mask: self.clone(),
        }
    }

    fn remember(
        &self,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        vars: &Vars,
        now: Duration,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.set(local, remote, vars, now);
        }
    }
}

type Vars = HashMap<String, Vec<u8>>;

#[derive(Debug, Default)]
struct StateStore {
    entries: HashMap<(Option<SocketAddr>, Option<SocketAddr>), (Vars, Duration)>,
}

impl StateStore {
    fn get(
        &mut self,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        now: Duration,
    ) -> Option<Vars> {
        let key = (local, remote);
        let expired = self
            .entries
            .get(&key)
            .is_some_and(|(_, at)| now.saturating_sub(*at) > STATE_TTL);
        if expired {
            self.entries.remove(&key);
        }
        self.entries.get(&key).map(|(vars, _)| vars.clone())
    }

    fn set(
        &mut self,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        vars: &Vars,
        now: Duration,
    ) {
        self.entries.insert((local, remote), (vars.clone(), now));
    }
}

fn valid_var(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        None => true,
        Some(first) if first.is_ascii_alphabetic() || first == b'_' => {
            bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }
        Some(_) => false,
    }
}

fn validate_expr(expr: &Expr) -> Option<()> {
    if expr.op.is_empty() || expr.args.is_empty() {
        return None;
    }
    for arg in &expr.args {
        match arg {
            ExprArg::Bytes(_) | ExprArg::U64(_) | ExprArg::Metadata(_) => {}
            ExprArg::Var(name) if !name.is_empty() && valid_var(name) => {}
            ExprArg::Var(_) => return None,
            ExprArg::Expr(nested) => validate_expr(nested)?,
        }
    }
    Some(())
}

/// One connection's pending handshake, shared by its read and write handles.
#[derive(Debug, Clone)]
pub struct HeaderRun {
    role: MaskRole,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    done: bool,
    failed: bool,
    vars: Vars,
    mask: HeaderCustom,
}

impl HeaderRun {
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Run the configured sequences once: the client writes then reads, the server reads then
    /// writes, and both stop on the first mismatch so a wrong peer never reaches the session.
    pub fn handshake<T: Read + Write>(&mut self, raw: &mut T, now: Duration) -> io::Result<()> {
        if self.done {
            return Ok(());
        }
        if self.failed {
            return Err(invalid("header auth failed"));
        }
        let result = self.handshake_once(raw, now);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn handshake_once<T: Read + Write>(&mut self, raw: &mut T, now: Duration) -> io::Result<()> {
        let mut ctx = Context::new(self.local, self.remote, std::mem::take(&mut self.vars));
        match self.role {
            MaskRole::Client => {
                let mut answered = 0usize;
                for sequence in &self.mask.clients {
                    write_sequence(raw, sequence, &mut ctx)?;
                    if let Some(server) = self.mask.servers.get(answered) {
                        read_sequence(raw, server, &mut ctx)?;
                        answered += 1;
                    }
                }
                while let Some(server) = self.mask.servers.get(answered) {
                    read_sequence(raw, server, &mut ctx)?;
                    answered += 1;
                }
            }
            MaskRole::Server => {
                let mut answered = 0usize;
                for (index, sequence) in self.mask.clients.iter().enumerate() {
                    if let Err(error) = read_sequence(raw, sequence, &mut ctx) {
                        if let Some(failure) = self.mask.errors.get(index) {
                            let _ = write_sequence(raw, failure, &mut ctx);
                        }
                        return Err(error);
                    }
                    if let Some(server) = self.mask.servers.get(answered) {
                        write_sequence(raw, server, &mut ctx)?;
                        answered += 1;
                    }
                }
                while let Some(server) = self.mask.servers.get(answered) {
                    write_sequence(raw, server, &mut ctx)?;
                    answered += 1;
                }
            }
        }
        self.mask.remember(self.local, self.remote, &ctx.vars, now);
        self.done = true;
        Ok(())
    }
}

#[derive(Debug)]
struct Context {
    vars: HashMap<String, Vec<u8>>,
    metadata: HashMap<String, Value>,
}

impl Context {
    fn new(local: Option<SocketAddr>, remote: Option<SocketAddr>, vars: Vars) -> Self {
        let mut metadata = HashMap::new();
        load_metadata(&mut metadata, "local", local);
        load_metadata(&mut metadata, "remote", remote);
        Self { vars, metadata }
    }

    fn sizes(&self) -> HashMap<String, usize> {
        self.vars
            .iter()
            .map(|(name, value)| (name.clone(), value.len()))
            .collect()
    }
}

#[derive(Debug, Clone)]
enum Value {
    Bytes(Vec<u8>),
    U64(u64),
}

impl Value {
    fn bytes(self) -> io::Result<Vec<u8>> {
        match self {
            Self::Bytes(value) => Ok(value),
            Self::U64(_) => Err(invalid("expression value is not bytes")),
        }
    }

    fn u64(&self) -> io::Result<u64> {
        match self {
            Self::U64(value) => Ok(*value),
            Self::Bytes(_) => Err(invalid("expression value is not u64")),
        }
    }
}

fn load_metadata(dst: &mut HashMap<String, Value>, prefix: &str, addr: Option<SocketAddr>) {
    let Some(addr) = addr else {
        return;
    };
    let port = u64::from(addr.port());
    dst.insert(format!("{prefix}_port"), Value::U64(port));
    match prefix {
        "remote" => {
            dst.insert("src_port_u16".to_owned(), Value::U64(port));
        }
        "local" => {
            dst.insert("dst_port_u16".to_owned(), Value::U64(port));
        }
        _ => {}
    }
    let ip = addr.ip();
    let v4 = match ip {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    };
    let Some(v4) = v4 else {
        return;
    };
    let value = u64::from(u32::from(v4));
    dst.insert(format!("{prefix}_ip4_u32"), Value::U64(value));
    match prefix {
        "remote" => {
            dst.insert("src_ip4_u32".to_owned(), Value::U64(value));
        }
        "local" => {
            dst.insert("dst_ip4_u32".to_owned(), Value::U64(value));
        }
        _ => {}
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn write_sequence<W: Write>(raw: &mut W, sequence: &Sequence, ctx: &mut Context) -> io::Result<()> {
    let mut merged = Vec::new();
    for item in &sequence.items {
        if item.delay.1 > 0 {
            flush(raw, &mut merged)?;
            park(item.delay);
        }
        let value = evaluate_item(item, ctx)?;
        merged.extend_from_slice(&value);
    }
    flush(raw, &mut merged)
}

fn flush<W: Write>(raw: &mut W, merged: &mut Vec<u8>) -> io::Result<()> {
    if merged.is_empty() {
        return Ok(());
    }
    raw.write_all(merged)?;
    merged.clear();
    Ok(())
}

fn park(delay: (i64, i64)) {
    let ms = between(delay.0, delay.1);
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms as u64));
    }
}

fn between(from: i64, to: i64) -> i64 {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    let span = to - from;
    if span == 0 || span == 1 {
        return from;
    }
    let mut raw = [0u8; 8];
    let Ok(()) = getrandom::fill(&mut raw) else {
        return from;
    };
    let step = i64::try_from(u64::from_le_bytes(raw) % span as u64).unwrap_or(i64::MAX);
    from.saturating_add(step)
}

fn evaluate_item(item: &Item, ctx: &mut Context) -> io::Result<Vec<u8>> {
    let value = if item.rand > 0 {
        random_bytes(item.rand as usize, item.rand_min as u8, item.rand_max as u8)?
    } else if let Some(packet) = item.packet.as_ref().filter(|packet| !packet.is_empty()) {
        packet.clone()
    } else if !item.reuse.is_empty() {
        ctx.vars
            .get(&item.reuse)
            .cloned()
            .ok_or_else(|| invalid("unknown variable"))?
    } else if let Some(expr) = &item.transform {
        evaluate_expr(expr, ctx)?.bytes()?
    } else {
        Vec::new()
    };
    if !item.save.is_empty() {
        ctx.vars.insert(item.save.clone(), value.clone());
    }
    Ok(value)
}

fn random_bytes(length: usize, low: u8, high: u8) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; length];
    getrandom::fill(&mut out).map_err(|error| io::Error::other(error.to_string()))?;
    let (low, high) = if low > high { (high, low) } else { (low, high) };
    if high.wrapping_sub(low) == 255 {
        return Ok(out);
    }
    let span = u16::from(high) - u16::from(low) + 1;
    for byte in &mut out {
        *byte = (u16::from(low) + u16::from(*byte) % span) as u8;
    }
    Ok(out)
}

fn read_sequence<R: Read>(raw: &mut R, sequence: &Sequence, ctx: &mut Context) -> io::Result<()> {
    for item in &sequence.items {
        let length = measure_item(item, &ctx.sizes())?;
        let mut buf = vec![0u8; length];
        raw.read_exact(&mut buf)?;
        if item.rand > 0 {
        } else if let Some(packet) = item.packet.as_ref().filter(|packet| !packet.is_empty()) {
            if packet != &buf {
                return Err(invalid("header auth failed"));
            }
        } else if !item.reuse.is_empty() {
            let Some(saved) = ctx.vars.get(&item.reuse) else {
                return Err(invalid("unknown variable"));
            };
            if saved != &buf {
                return Err(invalid("header auth failed"));
            }
        } else if let Some(expr) = &item.transform {
            let expected = evaluate_expr(expr, ctx)?.bytes()?;
            if expected != buf {
                return Err(invalid("header auth failed"));
            }
        }
        if !item.save.is_empty() {
            ctx.vars.insert(item.save.clone(), buf);
        }
    }
    Ok(())
}

fn measure_item(item: &Item, sizes: &HashMap<String, usize>) -> io::Result<usize> {
    let size = if item.rand > 0 {
        item.rand as usize
    } else if let Some(packet) = item.packet.as_ref().filter(|packet| !packet.is_empty()) {
        packet.len()
    } else if !item.reuse.is_empty() {
        *sizes
            .get(&item.reuse)
            .ok_or_else(|| invalid("unknown variable"))?
    } else if let Some(expr) = &item.transform {
        measure_expr(expr, sizes)?
    } else {
        0
    };
    Ok(size)
}

fn evaluate_expr(expr: &Expr, ctx: &Context) -> io::Result<Value> {
    match expr.op.as_str() {
        "concat" => {
            let mut out = Vec::new();
            for arg in &expr.args {
                out.extend_from_slice(&evaluate_arg(arg, ctx)?.bytes()?);
            }
            Ok(Value::Bytes(out))
        }
        "slice" => {
            let [source, offset, length] = args::<3>(expr)?;
            let source = evaluate_arg(source, ctx)?.bytes()?;
            let offset = evaluate_arg(offset, ctx)?.u64()?;
            let length = evaluate_arg(length, ctx)?.u64()?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid("slice out of bounds"))?;
            let start = usize::try_from(offset).map_err(|_| invalid("slice out of bounds"))?;
            let end = usize::try_from(end).map_err(|_| invalid("slice out of bounds"))?;
            let slice = source
                .get(start..end)
                .ok_or_else(|| invalid("slice out of bounds"))?;
            Ok(Value::Bytes(slice.to_vec()))
        }
        "xor16" => xor(expr, 0xFFFF, 2, ctx),
        "xor32" => xor(expr, 0xFFFF_FFFF, 4, ctx),
        "be16" => pack(expr, 2, true, ctx),
        "be32" => pack(expr, 4, true, ctx),
        "le16" => pack(expr, 2, false, ctx),
        "le32" => pack(expr, 4, false, ctx),
        "le64" => pack(expr, 8, false, ctx),
        "pad" => {
            let [source, target, fill] = args::<3>(expr)?;
            let source = evaluate_arg(source, ctx)?.bytes()?;
            let target = evaluate_arg(target, ctx)?.u64()?;
            let fill = evaluate_arg(fill, ctx)?.bytes()?;
            if fill.is_empty() {
                return Err(invalid("pad fill must not be empty"));
            }
            let target = usize::try_from(target).map_err(|_| invalid("pad target too long"))?;
            if target < source.len() {
                return Err(invalid("pad target shorter than source"));
            }
            let mut out = source;
            if out.capacity() < target {
                out.reserve(target - out.len());
            }
            while out.len() < target {
                let remaining = target - out.len();
                out.extend_from_slice(&fill[..remaining.min(fill.len())]);
            }
            Ok(Value::Bytes(out))
        }
        "truncate" => {
            let [source, length] = args::<2>(expr)?;
            let source = evaluate_arg(source, ctx)?.bytes()?;
            let length = evaluate_arg(length, ctx)?.u64()?;
            let length = usize::try_from(length).map_err(|_| invalid("truncate out of bounds"))?;
            source
                .get(..length)
                .map(|slice| Value::Bytes(slice.to_vec()))
                .ok_or_else(|| invalid("truncate out of bounds"))
        }
        "add" => binary(expr, ctx, |left, right| {
            left.checked_add(right)
                .ok_or_else(|| invalid("add overflow"))
        }),
        "sub" => binary(expr, ctx, |left, right| {
            left.checked_sub(right)
                .ok_or_else(|| invalid("sub underflow"))
        }),
        "and" => binary(expr, ctx, |left, right| Ok(left & right)),
        "or" => binary(expr, ctx, |left, right| Ok(left | right)),
        "shl" => shift(expr, ctx, |value, shift| {
            if shift >= 64 {
                return Err(invalid("shift out of range"));
            }
            value
                .checked_shl(shift as u32)
                .ok_or_else(|| invalid("shl overflow"))
        }),
        "shr" => shift(expr, ctx, |value, shift| {
            if shift >= 64 {
                return Err(invalid("shift out of range"));
            }
            Ok(value >> shift)
        }),
        other => Err(invalid(&format!("unsupported expr op: {other}"))),
    }
}

fn args<const N: usize>(expr: &Expr) -> io::Result<&[ExprArg; N]> {
    expr.args
        .as_slice()
        .try_into()
        .map_err(|_| invalid("expression has the wrong argument count"))
}

fn evaluate_arg(arg: &ExprArg, ctx: &Context) -> io::Result<Value> {
    match arg {
        ExprArg::Bytes(value) => Ok(Value::Bytes(value.clone())),
        ExprArg::U64(value) => Ok(Value::U64(*value)),
        ExprArg::Var(name) => ctx
            .vars
            .get(name)
            .cloned()
            .map(Value::Bytes)
            .ok_or_else(|| invalid("unknown variable")),
        ExprArg::Metadata(name) => ctx
            .metadata
            .get(name)
            .cloned()
            .ok_or_else(|| invalid("unknown metadata")),
        ExprArg::Expr(expr) => evaluate_expr(expr, ctx),
    }
}

fn xor(expr: &Expr, mask: u64, width: usize, ctx: &Context) -> io::Result<Value> {
    let [left, right] = args::<2>(expr)?;
    let left = evaluate_arg(left, ctx)?.u64()?;
    let right = evaluate_arg(right, ctx)?.u64()?;
    let limit = if width == 2 { 0xFFFF } else { 0xFFFF_FFFF };
    if left > limit || right > limit {
        return Err(invalid("xor overflow"));
    }
    Ok(Value::U64((left ^ right) & mask))
}

fn pack(expr: &Expr, width: usize, big: bool, ctx: &Context) -> io::Result<Value> {
    let [value] = args::<1>(expr)?;
    let value = evaluate_arg(value, ctx)?.u64()?;
    let mut out = vec![0u8; width];
    match (width, big) {
        (2, true) => {
            let value = u16::try_from(value).map_err(|_| invalid("pack overflow"))?;
            out.copy_from_slice(&value.to_be_bytes());
        }
        (2, false) => {
            let value = u16::try_from(value).map_err(|_| invalid("pack overflow"))?;
            out.copy_from_slice(&value.to_le_bytes());
        }
        (4, true) => {
            let value = u32::try_from(value).map_err(|_| invalid("pack overflow"))?;
            out.copy_from_slice(&value.to_be_bytes());
        }
        (4, false) => {
            let value = u32::try_from(value).map_err(|_| invalid("pack overflow"))?;
            out.copy_from_slice(&value.to_le_bytes());
        }
        (8, false) => out.copy_from_slice(&value.to_le_bytes()),
        _ => return Err(invalid("unsupported pack width")),
    }
    Ok(Value::Bytes(out))
}

fn binary(
    expr: &Expr,
    ctx: &Context,
    op: impl Fn(u64, u64) -> io::Result<u64>,
) -> io::Result<Value> {
    let [left, right] = args::<2>(expr)?;
    let left = evaluate_arg(left, ctx)?.u64()?;
    let right = evaluate_arg(right, ctx)?.u64()?;
    op(left, right).map(Value::U64)
}

fn shift(
    expr: &Expr,
    ctx: &Context,
    op: impl Fn(u64, u64) -> io::Result<u64>,
) -> io::Result<Value> {
    let [value, shift] = args::<2>(expr)?;
    let value = evaluate_arg(value, ctx)?.u64()?;
    let shift = evaluate_arg(shift, ctx)?.u64()?;
    if shift >= 64 {
        return Err(invalid("shift out of range"));
    }
    op(value, shift).map(Value::U64)
}

fn measure_expr(expr: &Expr, sizes: &HashMap<String, usize>) -> io::Result<usize> {
    match expr.op.as_str() {
        "concat" => {
            let mut total = 0usize;
            for arg in &expr.args {
                total = total
                    .checked_add(measure_arg(arg, sizes)?)
                    .ok_or_else(|| invalid("expression too long"))?;
            }
            Ok(total)
        }
        "slice" => {
            let [_, _, length] = args::<3>(expr)?;
            literal_u64(length)
        }
        "be16" | "le16" => Ok(2),
        "be32" | "le32" => Ok(4),
        "le64" => Ok(8),
        "pad" => {
            let [_, target, _] = args::<3>(expr)?;
            literal_u64(target)
        }
        "truncate" => {
            let [_, length] = args::<2>(expr)?;
            literal_u64(length)
        }
        other => Err(invalid(&format!("expr size is not bytes for op: {other}"))),
    }
}

fn literal_u64(arg: &ExprArg) -> io::Result<usize> {
    match arg {
        ExprArg::U64(value) => {
            usize::try_from(*value).map_err(|_| invalid("expression length too long"))
        }
        _ => Err(invalid("expression length must be u64")),
    }
}

fn measure_arg(arg: &ExprArg, sizes: &HashMap<String, usize>) -> io::Result<usize> {
    match arg {
        ExprArg::Bytes(value) => Ok(value.len()),
        ExprArg::U64(_) => Err(invalid("u64 argument has no byte width")),
        ExprArg::Var(name) => sizes
            .get(name)
            .copied()
            .ok_or_else(|| invalid("unknown variable")),
        ExprArg::Metadata(_) => Err(invalid("metadata has no byte width")),
        ExprArg::Expr(expr) => measure_expr(expr, sizes),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    struct Wire {
        input: Vec<u8>,
        at: usize,
        output: Vec<u8>,
        writes: usize,
    }

    impl Wire {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input,
                at: 0,
                output: Vec::new(),
                writes: 0,
            }
        }
    }

    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let take = buf.len().min(self.input.len() - self.at);
            buf[..take].copy_from_slice(&self.input[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn item() -> Item {
        Item::default()
    }

    fn mask(clients: Item, servers: Item) -> HeaderCustom {
        HeaderCustom::new(
            vec![Sequence {
                items: vec![clients],
            }],
            vec![Sequence {
                items: vec![servers],
            }],
            Vec::new(),
        )
        .expect("config is valid")
    }

    #[test]
    fn a_client_writes_its_sequence_then_checks_the_answer() {
        let mut client = item();
        client.rand = 2;
        client.rand_min = 0x2A;
        client.rand_max = 0x2A;
        client.save = "txid".to_owned();
        let mut expected = item();
        expected.reuse = "txid".to_owned();
        let run = mask(client, expected).open(MaskRole::Client, None, None, Duration::ZERO);
        let mut wire = Wire::new(vec![0x2A, 0x2A]);
        let mut run = run;
        run.handshake(&mut wire, Duration::ZERO)
            .expect("the answer matches");
        assert_eq!(wire.output, vec![0x2A, 0x2A]);
        assert_eq!(wire.at, 2);
        assert_eq!(wire.writes, 1);
    }

    #[test]
    fn a_server_reads_the_client_then_answers() {
        let mut client = item();
        client.rand = 2;
        client.rand_min = 0x2A;
        client.rand_max = 0x2A;
        client.save = "txid".to_owned();
        let mut answer = item();
        answer.packet = Some(vec![0x99, 0x01]);
        let mut run = mask(client, answer).open(MaskRole::Server, None, None, Duration::ZERO);
        let mut wire = Wire::new(vec![0x2A, 0x2A]);
        run.handshake(&mut wire, Duration::ZERO)
            .expect("the client matches");
        assert_eq!(wire.output, vec![0x99, 0x01]);
        assert_eq!(wire.writes, 1);
    }

    #[test]
    fn a_captured_value_survives_into_the_next_connection() {
        let mut client = item();
        client.rand = 2;
        client.rand_min = 7;
        client.rand_max = 7;
        client.save = "tx".to_owned();
        let header = HeaderCustom::new(
            vec![Sequence {
                items: vec![client],
            }],
            Vec::new(),
            Vec::new(),
        )
        .expect("config is valid");
        let mut first = header.open(MaskRole::Client, None, None, Duration::ZERO);
        first
            .handshake(&mut Wire::new(Vec::new()), Duration::ZERO)
            .expect("the first handshake does not read");
        let second = header.open(MaskRole::Client, None, None, Duration::ZERO);
        assert_eq!(second.vars.len(), 1);
        assert_eq!(second.vars.get("tx"), Some(&vec![7, 7]));
    }

    #[test]
    fn a_captured_value_expires_after_the_store_ttl() {
        let mut client = item();
        client.rand = 1;
        client.rand_min = 7;
        client.rand_max = 7;
        client.save = "tx".to_owned();
        let header = HeaderCustom::new(
            vec![Sequence {
                items: vec![client],
            }],
            Vec::new(),
            Vec::new(),
        )
        .expect("config is valid");
        let mut first = header.open(MaskRole::Client, None, None, Duration::ZERO);
        first
            .handshake(&mut Wire::new(Vec::new()), Duration::ZERO)
            .expect("the first handshake does not read");
        let live = header.open(MaskRole::Client, None, None, STATE_TTL);
        assert_eq!(live.vars.get("tx"), Some(&vec![7]));
        let expired = header.open(
            MaskRole::Client,
            None,
            None,
            STATE_TTL + Duration::from_millis(1),
        );
        assert!(expired.vars.is_empty());
    }

    #[test]
    fn a_mismatch_writes_the_configured_error_and_stops() {
        let mut expected = item();
        expected.packet = Some(vec![1, 2]);
        let mut failure = item();
        failure.packet = Some(vec![0xEE]);
        let header = HeaderCustom::new(
            vec![Sequence {
                items: vec![expected],
            }],
            Vec::new(),
            vec![Sequence {
                items: vec![failure],
            }],
        )
        .expect("config is valid");
        let mut run = header.open(MaskRole::Server, None, None, Duration::ZERO);
        let mut wire = Wire::new(vec![3, 4]);
        let error = run
            .handshake(&mut wire, Duration::ZERO)
            .expect_err("the client differs");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(wire.output, vec![0xEE]);
        assert_eq!(wire.writes, 1);
        assert!(
            run.handshake(&mut wire, Duration::ZERO).is_err(),
            "a failed handshake is final"
        );
        assert_eq!(wire.writes, 1, "and does not write the error twice");
    }

    #[test]
    fn expressions_pack_and_slice_the_values_the_sequences_carry() {
        let ctx = Context::new(None, None, Vars::default());
        let expr = Expr {
            op: "concat".to_owned(),
            args: vec![
                ExprArg::Bytes(vec![0xAA]),
                ExprArg::Expr(Expr {
                    op: "le16".to_owned(),
                    args: vec![ExprArg::U64(258)],
                }),
                ExprArg::Expr(Expr {
                    op: "be32".to_owned(),
                    args: vec![ExprArg::U64(0x0102_0304)],
                }),
            ],
        };
        let value = evaluate_expr(&expr, &ctx).expect("evaluates");
        assert_eq!(
            value.bytes().expect("bytes"),
            vec![0xAA, 0x02, 0x01, 0x01, 0x02, 0x03, 0x04]
        );
        let slice = Expr {
            op: "slice".to_owned(),
            args: vec![
                ExprArg::Bytes(vec![1, 2, 3, 4]),
                ExprArg::U64(1),
                ExprArg::U64(2),
            ],
        };
        assert_eq!(
            evaluate_expr(&slice, &ctx)
                .expect("evaluates")
                .bytes()
                .expect("bytes"),
            vec![2, 3]
        );
    }

    #[test]
    fn metadata_names_the_ports_of_the_socket_the_handshake_rides() {
        let local: SocketAddr = "127.0.0.1:1234".parse().expect("local");
        let remote: SocketAddr = "127.0.0.2:5678".parse().expect("remote");
        let ctx = Context::new(Some(local), Some(remote), Vars::default());
        let expr = Expr {
            op: "concat".to_owned(),
            args: vec![
                ExprArg::Expr(Expr {
                    op: "be16".to_owned(),
                    args: vec![ExprArg::Metadata("src_port_u16".to_owned())],
                }),
                ExprArg::Expr(Expr {
                    op: "be16".to_owned(),
                    args: vec![ExprArg::Metadata("dst_port_u16".to_owned())],
                }),
            ],
        };
        assert_eq!(
            evaluate_expr(&expr, &ctx)
                .expect("evaluates")
                .bytes()
                .expect("bytes"),
            vec![0x16, 0x2E, 0x04, 0xD2]
        );
    }

    #[test]
    fn a_width_overflow_is_an_error_not_a_wrap() {
        let ctx = Context::new(None, None, Vars::default());
        let expr = Expr {
            op: "xor16".to_owned(),
            args: vec![ExprArg::U64(0x1_0000), ExprArg::U64(1)],
        };
        assert!(evaluate_expr(&expr, &ctx).is_err());
    }
}
