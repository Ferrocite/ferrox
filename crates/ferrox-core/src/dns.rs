//! The DNS wire the DNS outbound answers: the first question of a message read
//! the way the pinned `xray-core` reads it through
//! `golang.org/x/net/dns/dnsmessage`, the messages its handler writes back, and
//! the decision its lane makes per message.
//!
//! Byte-identity is the pinned `xray-core`'s own handler, recorded over a
//! canned resolver by `scripts/dns-oracle` and replayed here octet for octet.

use std::sync::Arc;

/// The header the reference's parser reads before anything else; a message
/// below it never reaches a question in its parser.
const HEADER: usize = 12;

/// A message whose declared size the reference refuses: past this the
/// connection ends, not the message. The reference's `buf.Size`.
pub const MESSAGE_MAX: usize = 8192;

/// A name whose packed string the reference's parser weighs at this bound is a
/// parse error there: the bound is checked while the last label is appended, so
/// the longest name a parse accepts is exactly this long.
const NAME_MAX: usize = 254;

/// The most pointers the reference's parse follows before it refuses the name.
const POINTERS_MAX: u32 = 10;

/// The pointer prefix; its neighbors `0x40` and `0x80` are reserved and refuse
/// the label with it.
const POINTER_HIGH: u8 = 0xC0;

/// A question in the reference's `parseQuery` form: the name as the parse
/// spelled it — trailing dot, case and every byte kept — so the builder packs
/// what its `dnsmessage.Name` packs. The name rides the question: the longest a
/// parse accepts is `NAME_MAX`, so every message decides without a heap buffer.
#[derive(Debug)]
pub struct Question {
    pub id: u16,
    pub qtype: u16,
    name: [u8; NAME_MAX],
    len: usize,
}

impl Question {
    /// The name the parse spelled, trailing dot included.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }
}

/// The rule actions the reference's config carries, named as its own config
/// builder names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Direct,
    Drop,
    Return,
    Hijack,
}

impl Action {
    /// The action a JSON rule's own `action` value names; unknown is a config
    /// error in the reference, not an action this tree guesses.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "direct" => Self::Direct,
            "drop" => Self::Drop,
            "return" => Self::Return,
            "hijack" => Self::Hijack,
            _ => return None,
        })
    }

    fn applies_by_type(qtype: u16) -> bool {
        matches!(qtype, 1 | 28)
    }
}

/// The first question of `msg`, none when the reference's parser refuses it.
///
/// The parse is the reference's own: the message needs its twelve header
/// bytes, any question count but zero passes the header, the question needs
/// its name, its type and its class, a label refuses a dot byte, a name
/// arriving at the bound refuses, `0x40`/`0x80` label prefixes refuse, and
/// pointers are followed into any offset the message holds with the
/// reference's cap of ten — so the name is the dereferenced one, the form the
/// builder packs from.
pub fn parse_query(msg: &[u8]) -> Option<Question> {
    if msg.len() < HEADER {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    if u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return None;
    }
    let mut name = [0u8; NAME_MAX];
    let mut len = 0usize;
    let mut at = HEADER;
    let mut pointers = 0u32;
    loop {
        let start = *msg.get(at)?;
        if start & POINTER_HIGH == POINTER_HIGH {
            let next = *msg.get(at.checked_add(1)?)?;
            pointers += 1;
            if pointers > POINTERS_MAX {
                return None;
            }
            let target = (((start & 0x3F) as usize) << 8) | usize::from(next);
            if target >= msg.len() {
                return None;
            }
            at = target;
            continue;
        }
        if start & 0x3F != start {
            return None;
        }
        let span = usize::from(start);
        if span == 0 {
            at += 1;
            break;
        }
        let end = at.checked_add(span + 1)?;
        if end > msg.len() {
            return None;
        }
        if msg[at + 1..end].contains(&b'.') {
            return None;
        }
        if len + span >= NAME_MAX {
            return None;
        }
        name[len..len + span].copy_from_slice(&msg[at + 1..end]);
        len += span;
        name[len] = b'.';
        len += 1;
        at = end;
    }
    if len == 0 {
        name[0] = b'.';
        len = 1;
    }
    let qtype = read_u16(msg, at)?;
    read_u16(msg, at + 2)?;
    Some(Question {
        id,
        qtype,
        name,
        len,
    })
}

fn read_u16(msg: &[u8], at: usize) -> Option<u16> {
    let a = *msg.get(at)?;
    let b = *msg.get(at.checked_add(1)?)?;
    Some(u16::from_be_bytes([a, b]))
}

/// The name packed the way the reference's builder packs it: a root one zero
/// byte, otherwise every label prefixed and a zero byte after the last.
fn pack_name(out: &mut Vec<u8>, name: &[u8]) -> Option<()> {
    if name == b"." {
        out.push(0);
        return Some(());
    }
    for label in name[..name.len() - 1].split(|&byte| byte == b'.') {
        let len = label.len();
        if len > 63 {
            return None;
        }
        if len == 0 {
            return None;
        }
        out.push(len as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    Some(())
}

/// The bytes an answer's own name holds: the pointer at the question's own
/// offset, the form the builder's compression cache gave the record — except
/// where the name is the root, which the builder packed from its root
/// shortcut, so no pointer entry was ever cached.
fn packed_answer_name(name: &[u8]) -> &'static [u8] {
    if name == b"." {
        b"\x00"
    } else {
        b"\xC0\x0C"
    }
}

/// What the lane gets back for a hijack's lookup: the records and their TTL,
/// a resolution whose answer count is zero, the rcode its `RCodeError` means,
/// and the error without an rcode, the one the lane answers with nothing for.
#[derive(Debug, Clone)]
pub enum Resolve {
    Records { rdata: Vec<Vec<u8>>, ttl: u32 },
    AnsweredEmpty,
    Refused(u16),
    ErrHard,
}

/// The rules the config carries, in order, and the first one that names the
/// question decides.
#[derive(Clone)]
pub struct Rule {
    /// The types the rule answers to; empty answers any type.
    pub qtypes: Vec<u16>,
    /// The match a question's name must pass: none means the rule answers by
    /// type alone.
    pub domains: Option<Matcher>,
    pub action: Action,
    pub rcode: u16,
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("qtypes", &self.qtypes)
            .field("domains", &self.domains)
            .field("action", &self.action)
            .field("rcode", &self.rcode)
            .finish()
    }
}

/// The match a rule answers a question's name with, boxed because the config
/// builder's matcher is the tree's own; the [`std::fmt::Debug`] it reports is
/// the word "domains", not its insides.
#[derive(Clone)]
pub struct Matcher(Arc<dyn Fn(&str) -> bool + Send + Sync>);

impl Matcher {
    pub fn new(f: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    pub fn matches(&self, name: &str) -> bool {
        (self.0)(name)
    }
}

impl std::fmt::Debug for Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("domains")
    }
}

#[cfg(test)]
std::thread_local! {
    static NAME_FOLDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The name a rule matches: borrowed when already lowercase, else folded once into the one stack buffer this owns — never once per rule, and written where it lies, so a decide that folds pays no temporary to get it there.
struct Fold<'q> {
    looked: bool,
    borrowed: Option<&'q str>,
    folded: Option<([u8; NAME_MAX], usize)>,
}

impl<'q> Fold<'q> {
    fn empty() -> Self {
        Self {
            looked: false,
            borrowed: None,
            folded: None,
        }
    }

    /// Resolves the question's name into this fold, once for the whole rule list.
    fn look(&mut self, question: &'q Question) {
        self.looked = true;
        let name = question.name();
        let Some(matchable) = name.get(..name.len().saturating_sub(1)) else {
            return;
        };
        let Ok(text) = std::str::from_utf8(matchable) else {
            return;
        };
        if !text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            self.borrowed = Some(text);
            return;
        }
        #[cfg(test)]
        NAME_FOLDS.with(|folds| folds.set(folds.get() + 1));
        let (bytes, len) = self.folded.get_or_insert_with(|| ([0u8; NAME_MAX], 0));
        let lower = &mut bytes[..text.len()];
        lower.copy_from_slice(text.as_bytes());
        lower.make_ascii_lowercase();
        *len = text.len();
    }

    fn as_str(&self) -> Option<&str> {
        if let Some(text) = self.borrowed {
            return Some(text);
        }
        let (bytes, len) = self.folded.as_ref()?;
        std::str::from_utf8(&bytes[..*len]).ok()
    }
}

impl Rule {
    /// The reference's `DNSRule.apply`: any type the rule carries and, where
    /// it carries domains, the name the parse spelled — lowercased, trimmed
    /// of its trailing dot.
    pub fn applies(&self, question: &Question) -> bool {
        let mut fold = Fold::empty();
        self.applies_with(question, &mut fold)
    }

    fn applies_with<'q>(&self, question: &'q Question, fold: &mut Fold<'q>) -> bool {
        if !self.qtypes.is_empty() && !self.qtypes.contains(&question.qtype) {
            return false;
        }
        let Some(domains) = &self.domains else {
            return true;
        };
        if !fold.looked {
            fold.look(question);
        }
        let Some(name) = fold.as_str() else {
            return false;
        };
        domains.matches(name)
    }
}

/// What the lane writes for one message: the bytes it answers with, the whole
/// message forwarded through the tunnel unchanged, or nothing at all.
#[derive(Debug)]
pub enum Step {
    Reply(Vec<u8>),
    Forward,
    Quiet,
}

/// The decision the reference's handler makes per query: the rules in order,
/// then the type answers — A and AAAA are hijacked to the resolver while any
/// other type is rejected with the success rcode. A refusal the parse makes
/// is a quiet step.
///
/// A Hijack reply's rcode is the ride the lookup gave, never the rule's own:
/// the rule's rcode reaches only the reject a Hijack rule writes for a type
/// its resolver does not take.
pub fn decide(message: &[u8], rules: &[Rule], lookup: &dyn Fn(&[u8]) -> Resolve) -> Step {
    let Some(question) = parse_query(message) else {
        return Step::Quiet;
    };
    let decision = |action, rcode: u16| match action {
        Action::Drop => Step::Quiet,
        Action::Return => reject(question.id, question.qtype, question.name(), rcode)
            .map_or(Step::Quiet, Step::Reply),
        Action::Hijack => {
            if Action::applies_by_type(question.qtype) {
                resolve_step(&question, lookup)
            } else {
                reject(question.id, question.qtype, question.name(), rcode)
                    .map_or(Step::Quiet, Step::Reply)
            }
        }
        Action::Direct => Step::Forward,
    };
    let mut fold = Fold::empty();
    for rule in rules {
        if rule.applies_with(&question, &mut fold) {
            return decision(rule.action, rule.rcode);
        }
    }
    if question.qtype == 1 || question.qtype == 28 {
        resolve_step(&question, lookup)
    } else {
        decision(Action::Return, 0)
    }
}

/// The answer for a hijack: the records the resolver gave for the name, of
/// the question's own family, the ones its error codes answer with — and
/// nothing for the error whose rcode is zero and which is not the empty
/// response.
fn resolve_step(question: &Question, lookup: &dyn Fn(&[u8]) -> Resolve) -> Step {
    match lookup(question.name()) {
        Resolve::Records { rdata, ttl } => {
            ip_answer(question, 0, ttl, &rdata).map_or(Step::Quiet, Step::Reply)
        }
        Resolve::AnsweredEmpty => ip_answer(question, 0, 0, &[]).map_or(Step::Quiet, Step::Reply),
        Resolve::Refused(rcode) => {
            ip_answer(question, rcode, 0, &[]).map_or(Step::Quiet, Step::Reply)
        }
        Resolve::ErrHard => Step::Quiet,
    }
}

/// The answer: the reference's own `RESPONSE|AUTHORITATIVE|RECURSION_DESIRED|RECURSION_AVAILABLE` header pair
/// with the rcode, the question echoed with its type and class 1, and one record
/// per address of the question's own family, in resolver order, each carrying
/// the resolver's TTL. An address of the other family is skipped, the way the
/// reference's own write loop skips it.
///
/// Returns none when a name arrives the reference's own builder refuses — the
/// caller writes nothing, the reference's path through the builder's error.
///
/// Every record carries the builder's one compressed name: four bytes for A,
/// sixteen for AAAA.
pub fn ip_answer(
    question: &Question,
    rcode: u16,
    ttl: u32,
    records: &[Vec<u8>],
) -> Option<Vec<u8>> {
    let width = match question.qtype {
        28 => 16,
        _ => 4,
    };
    let matching = records
        .iter()
        .filter(|record| record.len() == width)
        .count() as u16;

    let mut out =
        Vec::with_capacity(HEADER + question.name().len() + 6 + records.len() * (16 + width));
    write_header(&mut out, question.id, rcode, 1, matching);
    pack_name(&mut out, question.name())?;
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    let pointer = packed_answer_name(question.name());
    for ip in records {
        if ip.len() != width {
            continue;
        }
        out.extend_from_slice(pointer);
        out.extend_from_slice(&question.qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(ip.len() as u16).to_be_bytes());
        out.extend_from_slice(ip);
    }
    Some(out)
}

/// The reject: the same header and echoed question the reference's reject
/// writes, and no answer records. A root name has no form the reference's own
/// reject can pack the question from — it writes nothing there.
pub fn reject(id: u16, qtype: u16, name: &[u8], rcode: u16) -> Option<Vec<u8>> {
    if name == b"." {
        return None;
    }
    let mut out = Vec::with_capacity(HEADER + name.len() + 6);
    write_header(&mut out, id, rcode, 1, 0);
    pack_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Some(out)
}

/// The reference's header pair: `RESPONSE|AUTHORITATIVE|RECURSION_DESIRED|RECURSION_AVAILABLE`
/// beneath the rcode's own bits, the way the reference's builder packs its
/// flags — a rule's rcode past the four flag bits rides into the whole word.
fn write_header(out: &mut Vec<u8>, id: u16, rcode: u16, questions: u16, answers: u16) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(0x8000u16 | 0x0400 | 0x0100 | 0x0080 | rcode).to_be_bytes());
    out.extend_from_slice(&questions.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&u16::to_be_bytes(0));
    out.extend_from_slice(&u16::to_be_bytes(0));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    const SCRIPT: &str = include_str!("../../../scripts/dns-oracle/script.txt");
    const EXPECTED: &str = include_str!("../../../scripts/dns-oracle/expected.txt");

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| {
                u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
                    .unwrap_or_else(|err| panic!("hex `{text}`: {err}"))
            })
            .collect()
    }

    /// The query the oracle drives the reference with, built the way
    /// dnsmessage packs it: the ID, the recursion bit, one question.
    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0; 6]);
        assert!(pack_name(&mut out, name.as_bytes()).is_some());
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    fn v4(text: &str) -> Vec<u8> {
        text.split('.')
            .map(|octet| octet.parse::<u8>().expect("v4"))
            .collect()
    }

    fn v6(text: &str) -> Vec<u8> {
        text.parse::<Ipv6Addr>().expect("v6").octets().to_vec()
    }

    /// The canned record a script line's `ips=` attr names, the way the
    /// oracle's own stand-in answers: the records, the empty response, or the
    /// refused rcode.
    fn canned(item: &str) -> Resolve {
        match item {
            "empty" => Resolve::AnsweredEmpty,
            "nxdomain" => Resolve::Refused(3),
            code => Resolve::Records {
                rdata: code
                    .split(',')
                    .map(|one| match one.strip_prefix("v4:") {
                        Some(rest) => v4(rest),
                        None => v6(one.strip_prefix("v6:").expect("canned")),
                    })
                    .collect(),
                ttl: 3600,
            },
        }
    }

    /// The rule a script line's `rule=` names; the two domain forms the
    /// script uses are `full:` equality and the plain substring.
    fn rule(item: &str) -> Rule {
        let mut parts = item.split('/');
        let qtypes = match parts.next().expect("rule qtype") {
            "*" => Vec::new(),
            hex => vec![u16::from_str_radix(hex, 16).expect("rule qtype")],
        };
        let domain = parts.next().expect("rule domain");
        let action = parts.next().expect("rule action");
        let rcode = match parts.next().expect("rule rcode") {
            "-" => 0,
            hex => u16::from_str_radix(hex, 16).expect("rule rcode"),
        };
        let domains = if let Some(full) = domain.strip_prefix("full:") {
            let full = full.to_owned();
            Matcher::new(move |name: &str| name == full)
        } else {
            let needle = domain.to_owned();
            Matcher::new(move |name: &str| name.contains(&needle))
        };
        Rule {
            qtypes,
            domains: Some(domains),
            action: Action::from_name(action).expect("rule action"),
            rcode,
        }
    }

    /// One scripted line in the forms `decide` reads.
    struct Case {
        kind: &'static str,
        tcp: bool,
        message: Vec<u8>,
        rule: Option<Rule>,
        lookup: Option<Resolve>,
        feed: Vec<u8>,
    }

    fn case(line: &'static str) -> Case {
        let mut fields = line.split_whitespace();
        let kind = fields.next().expect("kind");
        let tcp = fields.next().expect("network") == "tcp";
        let mut case = Case {
            kind,
            tcp,
            message: Vec::new(),
            rule: None,
            lookup: None,
            feed: Vec::new(),
        };
        match kind {
            "broken" => case.message = unhex(fields.next().expect("raw query")),
            other => {
                assert!(class_of(other).is_some(), "unknown kind {other}");
                let id = u16::from_str_radix(fields.next().expect("id"), 16).expect("id");
                let name = fields.next().expect("name");
                let qtype = u16::from_str_radix(fields.next().expect("qtype"), 16).expect("qtype");
                case.message = query(id, name, qtype);
                for attr in fields {
                    let (key, value) = attr.split_once('=').expect("attr form");
                    match key {
                        "ips" => case.lookup = Some(canned(value)),
                        "rule" => case.rule = Some(rule(value)),
                        "feed" => case.feed = unhex(value),
                        // The tunnel's own dest the direct case named; the replay never dials it.
                        "dest" => {}
                        "ttl" => {
                            let ttl = value.parse::<u32>().expect("ttl");
                            if let Some(Resolve::Records { ttl: named, .. }) = &mut case.lookup {
                                *named = ttl;
                            }
                        }
                        other => panic!("unknown attr {other}"),
                    }
                }
            }
        }
        case
    }

    /// The kinds the script carries in its `<kind>` column, none for the raw
    /// `broken` lines.
    fn class_of(kind: &str) -> Option<()> {
        match kind {
            "hijack" | "reject" | "drop" | "direct" | "oversize" => Some(()),
            _ => None,
        }
    }

    /// The bytes the lane writes for one answer over one network: raw over
    /// UDP, framed by length over TCP.
    fn frame(body: &[u8], tcp: bool) -> Vec<u8> {
        if !tcp {
            return body.to_vec();
        }
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// The replayed bytes for one scripted line, the way the lanes write
    /// them: the decision, then the network's frame of what was written.
    fn replay(line: &'static str) -> Vec<u8> {
        let case = case(line);
        let rules: Vec<Rule> = case.rule.iter().cloned().collect();
        let lookup = |_: &[u8]| case.lookup.clone().unwrap_or(Resolve::AnsweredEmpty);
        let decision = match case.kind {
            "direct" => Step::Forward,
            // Dropped, and oversized: the lane's own frame read refuses the size before any decision.
            "drop" | "oversize" => Step::Quiet,
            _ => decide(&case.message, &rules, &lookup),
        };
        match decision {
            Step::Reply(reply) => frame(&reply, case.tcp),
            Step::Forward => frame(&case.feed, case.tcp),
            Step::Quiet => Vec::new(),
        }
    }

    /// The record: the reference's own bytes for every case, replayed octet
    /// for octet.
    #[test]
    fn the_answer_is_the_bytes_the_pinned_go_writes() {
        let script: Vec<&'static str> = SCRIPT
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('/') && !line.starts_with('#'))
            .collect();
        let mut expecteds = Vec::new();
        for line in EXPECTED.lines() {
            let line = line.trim();
            if let Some(hex) = line.strip_prefix("BYTES").map(str::trim) {
                expecteds.push(unhex(hex));
            } else {
                assert!(line.is_empty(), "unexpected record line `{line}`");
            }
        }
        assert_eq!(script.len(), expecteds.len(), "script and record differ");
        for (line, expected) in script.into_iter().zip(expecteds) {
            let replayed = replay(line);
            if expected != replayed {
                let hex = |bytes: &[u8]| {
                    bytes
                        .iter()
                        .fold(String::new(), |acc, byte| format!("{acc}{byte:02x}"))
                };
                panic!(
                    "case `{line}`\nexpected {}\nreplayed {}",
                    hex(&expected),
                    hex(&replayed)
                );
            }
        }
    }

    /// The parse's refusals: a short header, a question count of zero, a dot
    /// inside a label, a reserved label prefix, a pointer aimed past the
    /// buffer.
    #[test]
    fn the_parse_refuses_what_the_reference_refuses() {
        assert!(parse_query(&[]).is_none());
        assert!(parse_query(&[0u8; 11]).is_none());
        // The full header with a zero question count has nothing to read.
        assert!(parse_query(&[0u8; 12]).is_none());
        // A zero count with a question block waiting behind it: the header's own count serves the read, so the block is not.
        assert!(parse_query(&unhex("00010100000000000000000001610000010001")).is_none());

        // A label whose bytes end in a dot.
        assert!(parse_query(&unhex("00010100000100000000000002612e620000010001")).is_none());

        // Both label prefixes the reference reserves.
        assert!(parse_query(&unhex("0001010000010000000000008001610000010001")).is_none());
        assert!(parse_query(&unhex("0001010000010000000000004001610000010001")).is_none());

        // A pointer aimed at the buffer's own length: past the last byte.
        assert!(parse_query(&unhex("000101000001000000000000c0ff00010001")).is_none());
    }

    /// A pointer that aims at itself: the cap the reference carries is ten
    /// pointer hops, and past it the name refuses.
    #[test]
    fn the_pointer_loop_refuses_at_the_cap() {
        // The pointer reads its own offset: every hop counts one, and the eleventh refuses.
        assert!(parse_query(&unhex("000101000001000000000000c00c")).is_none());
        // A pair of pointers bouncing between their own offsets: the cap catches it before the name's bound does.
        assert!(parse_query(&unhex("000101000001000000000000c00ec00c")).is_none());
    }

    /// The bound on names: a run of labels whose packed form lands at 254
    /// bytes is the longest the parse takes, one byte more refuses.
    #[test]
    fn the_name_bound_matches_the_reference() {
        // Five labels of 42 bytes and a dot, then one more label: its dot closes the name at the bound.
        let build = |last: usize| {
            let mut message = vec![0u8; 12];
            message[0] = 1;
            message[5] = 1;
            for _ in 0..5 {
                message.extend_from_slice(&[42]);
                message.extend(std::iter::repeat_n(b'a', 42));
            }
            message.extend_from_slice(&[last as u8]);
            message.extend(std::iter::repeat_n(b'a', last));
            message.extend_from_slice(&[0, 0, 1, 0, 1]);
            message
        };
        // 5 * 43 + 39 + 1 = 254 bytes: the longest name the parse accepts.
        assert_eq!(
            parse_query(&build(38)).expect("parses at the bound").qtype,
            1
        );
        // One label byte more: 255 bytes, refused.
        assert!(parse_query(&build(39)).is_none());
    }

    /// A forwarded question is the lane's common decision and its answer is a constant: the name
    /// rides the question, the rule match folds it where it lies, and nothing is opened.
    #[test]
    fn a_forwarded_question_is_decided_without_an_allocation() {
        let message = query(0x1234, "WWW.Example.COM.", 1);
        let rules = vec![Rule {
            qtypes: Vec::new(),
            domains: Some(Matcher::new(|name: &str| name == "www.example.com")),
            action: Action::Direct,
            rcode: 0,
        }];
        let (step, counts) =
            crate::alloc_count::measure(|| decide(&message, &rules, &|_| Resolve::AnsweredEmpty));
        assert!(matches!(step, Step::Forward), "the rule forwards it");
        assert_eq!(counts.allocs, 0, "a forwarded question opens no buffer");
    }

    /// A hijacked question's only buffer is the answer it returns: the name, the match and the
    /// answer's own shape open nothing.
    #[test]
    fn a_hijacked_question_opens_only_its_answer() {
        let message = query(0x4321, "Example.COM.", 1);
        let (step, counts) =
            crate::alloc_count::measure(|| decide(&message, &[], &|_| Resolve::AnsweredEmpty));
        let Step::Reply(answer) = step else {
            panic!("a type-A question is hijacked");
        };
        assert_eq!(counts.allocs, 1, "the answer is the one buffer");
        assert_eq!(
            answer.len(),
            message.len(),
            "a header and the echoed question"
        );
    }

    /// The decide probe: a direct forward its domains rule names, a rule
    /// return, two hijacks the lookup answers, and a malformed name, walked
    /// 4096 times, so the frame the count harness reads is the method and
    /// not the caller that inlined it.
    #[test]
    fn the_decide_probe_costs_the_parse_rules_and_answer_and_nothing_else() {
        let messages = [
            query(0x1234, "example.com.", 1),
            query(0x1234, "mil.example.", 28),
            query(0x1234, "blocked.example.", 1),
            query(0x1234, "example.com.", 28),
        ];
        let rules = vec![
            rule("*/blocked.example/return/1"),
            rule("*/example.com/direct/-"),
        ];
        let resolve = canned("v4:192.0.2.9");
        let broken = unhex("00010100000100000000000001610000010001");
        let mut answer = 0usize;
        for _ in 0..4096 {
            let lookup = |_: &[u8]| resolve.clone();
            for message in &messages {
                if let Step::Reply(reply) = decide(message, &rules, &lookup) {
                    answer += reply.len();
                }
            }
            if let Step::Reply(reply) = decide(&broken, &rules, &lookup) {
                answer += reply.len();
            }
        }
        std::hint::black_box(answer);
        assert!(answer > 0, "the probe decided nothing");
    }

    /// Three domain rules, the last one naming the question: the borrow is the whole match.
    #[test]
    fn a_lowercase_name_matches_the_rule_list_without_a_fold() {
        let rules: Vec<Rule> = ["first.example", "second.example", "www.example.com"]
            .iter()
            .copied()
            .map(|needle| Rule {
                qtypes: Vec::new(),
                domains: Some(Matcher::new(move |name: &str| name.ends_with(needle))),
                action: Action::Direct,
                rcode: 0,
            })
            .collect();
        let lookup = |_: &[u8]| canned("empty");
        NAME_FOLDS.with(|folds| folds.set(0));
        let step = decide(&query(0x1234, "www.example.com.", 1), &rules, &lookup);
        assert!(
            matches!(step, Step::Forward),
            "the last rule names the question"
        );
        assert_eq!(
            NAME_FOLDS.with(std::cell::Cell::get),
            0,
            "a lowercase name reaches the matcher as it arrived"
        );
    }

    /// The same three rules over a mixed-case name: one fold, not one per rule, and the same match.
    #[test]
    fn a_mixed_case_name_is_folded_once_for_the_rule_list() {
        let rules: Vec<Rule> = ["first.example", "second.example", "www.example.com"]
            .iter()
            .copied()
            .map(|needle| Rule {
                qtypes: Vec::new(),
                domains: Some(Matcher::new(move |name: &str| name.ends_with(needle))),
                action: Action::Direct,
                rcode: 0,
            })
            .collect();
        let lookup = |_: &[u8]| canned("empty");
        NAME_FOLDS.with(|folds| folds.set(0));
        let step = decide(&query(0x1234, "WWW.Example.COM.", 1), &rules, &lookup);
        assert!(
            matches!(step, Step::Forward),
            "the folded name still matches"
        );
        assert_eq!(
            NAME_FOLDS.with(std::cell::Cell::get),
            1,
            "one fold for three domain rules"
        );
    }
}

/// The EDNS0 settings a query carries: the client subnet the reference puts in
/// option 8 with its fixed masks (24 for IPv4, 96 for IPv6), and the zero
/// padding option 12 whose length the `DoH` lane randomises.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Edns {
    pub client_ip: Option<std::net::IpAddr>,
    pub padding: usize,
}

impl Edns {
    /// Whether the query carries an OPT record at all: the reference emits one
    /// only when it has a subnet or padding to put in it.
    pub fn is_some(&self) -> bool {
        self.client_ip.is_some() || self.padding != 0
    }
}

/// One question packed the way the reference's `dnsmessage.Message.Pack`
/// packs it: recursion desired, one question, and an OPT record whose class is
/// the UDP payload size 1350, whose extended rcode is 0xfe and whose DNSSEC-OK
/// bit is set. The name is the FQDN form the reference's `Fqdn` keeps, trailing
/// dot included, so `pack_name` drops the final dot as the reference does.
pub fn build_query(id: u16, name: &[u8], qtype: u16, edns: Option<Edns>) -> Option<Vec<u8>> {
    if name.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(HEADER + name.len() + 16);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    pack_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    let Some(edns) = edns.filter(Edns::is_some) else {
        return Some(out);
    };
    out[10..12].copy_from_slice(&1u16.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&41u16.to_be_bytes());
    out.extend_from_slice(&1350u16.to_be_bytes());
    out.extend_from_slice(&0xfe00_8000u32.to_be_bytes());
    let mut body = Vec::new();
    if let Some(ip) = edns.client_ip {
        body.extend_from_slice(&8u16.to_be_bytes());
        let (family, bytes, mask) = match ip {
            std::net::IpAddr::V4(ip) => (1u16, ip.octets().to_vec(), 24u8),
            std::net::IpAddr::V6(ip) => (2u16, ip.octets().to_vec(), 96u8),
        };
        let need = usize::from(mask).div_ceil(8);
        let mut data = Vec::with_capacity(4 + need);
        data.extend_from_slice(&family.to_be_bytes());
        data.push(mask);
        data.push(0);
        data.extend_from_slice(&bytes[..need]);
        body.extend_from_slice(&(data.len() as u16).to_be_bytes());
        body.extend_from_slice(&data);
    }
    if edns.padding != 0 {
        body.extend_from_slice(&12u16.to_be_bytes());
        body.extend_from_slice(&(edns.padding as u16).to_be_bytes());
        body.resize(body.len() + edns.padding, 0);
    }
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    Some(out)
}

/// One answer record as the reference's response parser reads it: the type,
/// the TTL, and the raw rdata. The lane keeps whatever section the response
/// carried; filtering to A and AAAA is the resolver's own choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerRecord {
    pub kind: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// The response fields the resolver reads: the header's id, rcode and
/// truncation bit, and every answer record in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub id: u16,
    pub rcode: u16,
    pub truncated: bool,
    pub records: Vec<AnswerRecord>,
}

/// Parse the header, the question section and the answers of a response. A
/// message too short to hold its own counts, a name that hops more than ten
/// pointers, a label that refuses a dot byte, and a record that runs past the
/// message all refuse the parse, the way the reference's parser does.
pub fn parse_answer(msg: &[u8]) -> Option<Answer> {
    if msg.len() < HEADER {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let questions = usize::from(u16::from_be_bytes([msg[4], msg[5]]));
    let answers = usize::from(u16::from_be_bytes([msg[6], msg[7]]));
    let mut at = HEADER;
    for _ in 0..questions {
        skip_wire_name(msg, &mut at)?;
        at = at.checked_add(4).filter(|end| *end <= msg.len())?;
    }
    let mut records = Vec::with_capacity(answers);
    for _ in 0..answers {
        skip_wire_name(msg, &mut at)?;
        let kind = read_u16(msg, at)?;
        read_u16(msg, at.checked_add(2)?)?;
        let ttl = u32::from_be_bytes([
            *msg.get(at.checked_add(4)?)?,
            *msg.get(at.checked_add(5)?)?,
            *msg.get(at.checked_add(6)?)?,
            *msg.get(at.checked_add(7)?)?,
        ]);
        let length = usize::from(read_u16(msg, at.checked_add(8)?)?);
        let start = at.checked_add(10)?;
        let end = start.checked_add(length).filter(|end| *end <= msg.len())?;
        records.push(AnswerRecord {
            kind,
            ttl,
            rdata: msg[start..end].to_vec(),
        });
        at = end;
    }
    Some(Answer {
        id,
        rcode: flags & 0x000f,
        truncated: flags & 0x0200 != 0,
        records,
    })
}

/// The offset just past the name at `*at`; a pointer ends the name there and
/// is then followed only to validate the labels it names.
fn skip_wire_name(msg: &[u8], at: &mut usize) -> Option<()> {
    let next = *at;
    let mut cursor = next;
    let mut after = None;
    let mut pointers = 0u32;
    loop {
        let start = *msg.get(cursor)?;
        if start & POINTER_HIGH == POINTER_HIGH {
            let low = *msg.get(cursor.checked_add(1)?)?;
            pointers += 1;
            if pointers > POINTERS_MAX {
                return None;
            }
            after.get_or_insert(cursor + 2);
            let target = (((start & 0x3F) as usize) << 8) | usize::from(low);
            if target >= msg.len() {
                return None;
            }
            cursor = target;
            continue;
        }
        if start & 0x3F != start {
            return None;
        }
        let span = usize::from(start);
        if span == 0 {
            *at = after.unwrap_or(cursor + 1);
            return Some(());
        }
        let end = cursor.checked_add(span + 1)?;
        if end > msg.len() || msg[cursor + 1..end].contains(&b'.') {
            return None;
        }
        cursor = end;
    }
}

#[cfg(test)]
mod resolver_wire_tests {
    use super::*;

    #[test]
    fn a_query_is_the_references_pack() {
        let query = build_query(0x1234, b"example.com.", 1, None).expect("packs");
        assert_eq!(
            query,
            [
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
            ]
        );
    }

    #[test]
    fn an_edns_query_carries_the_references_opt_record() {
        let query = build_query(
            0,
            b"example.com.",
            28,
            Some(Edns {
                client_ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))),
                padding: 3,
            }),
        )
        .expect("packs");
        let root = query.len() - 29;
        assert_eq!(
            &query[root..root + 11],
            &[0, 0, 41, 0x05, 0x46, 0xfe, 0x00, 0x80, 0x00, 0, 18]
        );
        assert_eq!(
            &query[root + 11..],
            &[0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2, 0, 12, 0, 3, 0, 0, 0]
        );
    }

    #[test]
    fn a_response_reads_its_answers_in_wire_order() {
        let answer = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01, 0xc0,
            0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1, 0xc0,
            0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10, 0x20, 0x01, 0x0d,
            0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let parsed = parse_answer(&answer).expect("parses");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.rcode, 0);
        assert!(!parsed.truncated);
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].kind, 1);
        assert_eq!(parsed.records[0].rdata, vec![192, 0, 2, 1]);
        assert_eq!(parsed.records[1].kind, 28);
        assert_eq!(parsed.records[1].ttl, 60);
    }

    #[test]
    fn a_message_that_runs_past_its_length_refuses() {
        let mut answer = vec![0u8; HEADER];
        answer[4..6].copy_from_slice(&1u16.to_be_bytes());
        answer[6..8].copy_from_slice(&1u16.to_be_bytes());
        answer.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(parse_answer(&answer).is_none());
    }
}
