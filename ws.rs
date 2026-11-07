//! Минимальный WebSocket (RFC 6455) на чистом std: рукопожатие и кадры.

use std::io::{self, Read, Write};

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}

pub fn accept_key(key: &str) -> String {
    base64(&sha1(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()))
}

pub enum Frame {
    Text(String),
    Ping(Vec<u8>),
    Pong,
    Close,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Читает один кадр клиента. Кадры клиента обязаны быть замаскированными.
/// Фрагментированные и бинарные кадры не поддерживаются (браузер шлёт короткий текст целиком).
pub fn read_frame<R: Read>(r: &mut R, max: usize) -> io::Result<Frame> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h)?;
    let fin = h[0] & 0x80 != 0;
    let opcode = h[0] & 0x0f;
    if h[0] & 0x70 != 0 || !fin && opcode < 8 {
        return Err(bad("фрагментация не поддерживается"));
    }
    if !matches!(opcode, 1 | 8 | 9 | 10) {
        return Err(bad("неподдерживаемый тип кадра"));
    }
    let control = opcode >= 8;
    if control && (!fin || (h[1] & 0x7f) > 125) {
        return Err(bad("неверный управляющий кадр"));
    }
    if h[1] & 0x80 == 0 {
        return Err(bad("кадр не замаскирован"));
    }
    let len = match h[1] & 0x7f {
        126 => {
            let mut b = [0u8; 2];
            r.read_exact(&mut b)?;
            let n = u16::from_be_bytes(b) as usize;
            if n < 126 {
                return Err(bad("не минимальная длина кадра"));
            }
            n
        }
        127 => {
            let mut b = [0u8; 8];
            r.read_exact(&mut b)?;
            let n = u64::from_be_bytes(b);
            if n & (1u64 << 63) != 0 || n <= 0xffff {
                return Err(bad("неверная длина кадра"));
            }
            usize::try_from(n).map_err(|_| bad("кадр слишком большой"))?
        }
        n => n as usize,
    };
    if len > max {
        return Err(bad("кадр слишком большой"));
    }
    let mut mask = [0u8; 4];
    r.read_exact(&mut mask)?;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    match opcode {
        1 => String::from_utf8(payload).map(Frame::Text).map_err(|_| bad("не UTF-8")),
        8 if payload.len() == 1 => Err(bad("неверный close-кадр")),
        8 => Ok(Frame::Close),
        9 => Ok(Frame::Ping(payload)),
        10 => Ok(Frame::Pong),
        _ => Err(bad("неподдерживаемый тип кадра")),
    }
}

pub fn write_frame<W: Write>(w: &mut W, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut f = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => f.push(n as u8),
        n if n <= 0xffff => {
            f.push(126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(payload);
    w.write_all(&f)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_handshake_example() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn sha1_known_vectors() {
        let hex = |d: [u8; 20]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        let long = vec![b'a'; 1000];
        assert_eq!(hex(sha1(&long)), "291e9a6c66994949b57ba5e650361e98fc36b1ba");
    }

    fn masked(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x12, 0x34, 0x56, 0x78];
        let mut f = vec![0x80 | opcode];
        match payload.len() {
            n if n < 126 => f.push(0x80 | n as u8),
            n => {
                f.push(0x80 | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        f.extend_from_slice(&mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        f
    }

    #[test]
    fn reads_masked_text_short_and_extended() {
        for text in ["привет", &"я".repeat(300)] {
            let data = masked(1, text.as_bytes());
            match read_frame(&mut &data[..], 4096).unwrap() {
                Frame::Text(t) => assert_eq!(t, text),
                _ => panic!("ожидался текст"),
            }
        }
    }

    #[test]
    fn rejects_unmasked_oversized_and_fragmented() {
        assert!(read_frame(&mut &[0x81u8, 0x01, b'x'][..], 4096).is_err());
        let big = masked(1, &vec![b'x'; 300]);
        assert!(read_frame(&mut &big[..], 100).is_err());
        let mut frag = masked(1, b"hi");
        frag[0] &= 0x7f; // FIN=0
        assert!(read_frame(&mut &frag[..], 4096).is_err());
    }

    #[test]
    fn rejects_invalid_control_frames_and_reserved_opcodes() {
        // Ping must be final and no longer than 125 bytes.
        let mut ping = masked(9, b"ok");
        ping[0] &= 0x7f;
        assert!(read_frame(&mut &ping[..], 4096).is_err());

        let long_ping = masked(9, &vec![b'x'; 126]);
        assert!(read_frame(&mut &long_ping[..], 4096).is_err());

        let reserved = masked(3, b"x");
        assert!(read_frame(&mut &reserved[..], 4096).is_err());

        let bad_close = masked(8, b"x");
        assert!(read_frame(&mut &bad_close[..], 4096).is_err());
    }

    #[test]
    fn writes_server_frames() {
        let mut out = Vec::new();
        write_frame(&mut out, 1, b"hi").unwrap();
        assert_eq!(out, [0x81, 2, b'h', b'i']);
        let mut out = Vec::new();
        write_frame(&mut out, 1, &vec![b'x'; 200]).unwrap();
        assert_eq!(&out[..4], &[0x81, 126, 0, 200]);
    }
}
