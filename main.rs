//! Анонимный чат «Эхо»: HTTP + WebSocket на чистом std (без внешних крейтов).
//! Страница и счётчик онлайна отдаются по HTTP, сам чат идёт по WebSocket (/ws).

mod state;
mod ws;

use state::{json_str, Prefs, State};
use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::hash::{BuildHasher, Hasher};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use ws::Frame;

const INDEX_HTML: &str = include_str!("index.html");
const HEARTBEAT: Duration = Duration::from_secs(15);
/// Клиент шлёт пинг каждые 15 с; если тишина дольше, соединение считается мёртвым.
const WS_READ_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_FRAME: usize = 4096;
const MAX_HEAD: u64 = 16 * 1024;
const MAX_CONNECTIONS: usize = 512;

struct Shared {
    state: Mutex<State>,
    cv: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

struct Req {
    method: String,
    path: String,
    ip: IpAddr,
    host: Option<String>,
    origin: Option<String>,
    ws_key: Option<String>,
    upgrade_ws: bool,
    connection_upgrade: bool,
    ws_version_13: bool,
}

struct Resp {
    status: u16,
    ctype: &'static str,
    body: String,
}

fn json(status: u16, body: String) -> Resp {
    Resp { status, ctype: "application/json; charset=utf-8", body }
}

fn err_resp(code: u16, msg: &str) -> Resp {
    json(code, format!("{{\"error\":{}}}", json_str(msg)))
}

/// Непредсказуемый внутренний идентификатор сессии; это не токен авторизации.
fn new_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut out = String::new();
    for _ in 0..2 {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

/// Число доверенных прокси перед сервером (CHAT_PROXY_HOPS). 0 — прокси нет.
fn proxy_hops() -> usize {
    static HOPS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *HOPS.get_or_init(|| std::env::var("CHAT_PROXY_HOPS").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

/// Настоящий IP клиента: берём адрес с конца X-Forwarded-For, отступив на
/// `hops - 1` доверенных прокси (левые значения клиент может подделать).
fn client_ip(peer: IpAddr, xff: Option<&str>, hops: usize) -> IpAddr {
    if hops == 0 {
        return peer;
    }
    xff.and_then(|h| {
        let parts: Vec<&str> = h.split(',').map(str::trim).collect();
        parts.len().checked_sub(hops).and_then(|i| parts[i].parse().ok())
    })
    .unwrap_or(peer)
}

/// Защита от чужих сайтов: если браузер прислал Origin, он должен совпадать с Host.
fn origin_ok(origin: Option<&str>, host: Option<&str>) -> bool {
    match (origin, host) {
        (None, _) => true,
        (Some(o), Some(h)) => o.split_once("://").map_or(false, |(_, rest)| rest.eq_ignore_ascii_case(h)),
        (Some(_), None) => false,
    }
}

fn read_request(stream: &TcpStream, peer: IpAddr) -> Option<Req> {
    let mut rd = BufReader::new(stream.take(MAX_HEAD));
    let mut line = String::new();
    rd.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let version = parts.next()?;
    if version != "HTTP/1.1" || parts.next().is_some() || !target.starts_with('/') || target.starts_with("//")
        || target.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return None;
    }
    let path = target.split('?').next().unwrap_or("/").to_string();
    let (mut host, mut origin, mut ws_key, mut xff) = (None, None, None, None);
    let (mut upgrade_ws, mut connection_upgrade, mut ws_version_13) = (false, false, false);
    let mut header_count = 0usize;
    let mut seen_headers = HashSet::new();
    loop {
        let mut h = String::new();
        if rd.read_line(&mut h).ok()? == 0 {
            return None;
        }
        if h.len() > 8 * 1024 {
            return None;
        }
        let h = h.trim_end_matches(&['\r', '\n'][..]);
        if h.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > 64 || h.starts_with(' ') || h.starts_with('\t') {
            return None;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)) {
                return None;
            }
            let v = v.trim().to_string();
            if v.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
                return None;
            }
            let name = k.to_ascii_lowercase();
            if !seen_headers.insert(name.clone()) {
                return None;
            }
            match name.as_str() {
                "host" => host = Some(v),
                "origin" => origin = Some(v),
                "sec-websocket-key" => ws_key = Some(v),
                "x-forwarded-for" => xff = Some(v),
                "upgrade" => upgrade_ws = v.eq_ignore_ascii_case("websocket"),
                "connection" => {
                    connection_upgrade = v.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
                }
                "sec-websocket-version" => ws_version_13 = v == "13",
                _ => {}
            }
        } else {
            return None;
        }
    }
    if host.as_deref().map_or(true, |h| h.is_empty() || h.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace())) {
        return None;
    }
    let ip = client_ip(peer, xff.as_deref(), proxy_hops());
    Some(Req { method, path, ip, host, origin, ws_key, upgrade_ws, connection_upgrade, ws_version_13 })
}

fn response_head(r: &Resp) -> String {
    let reason = match r.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Error",
    };
    format!("HTTP/1.1 {} {}\\r\\nContent-Type: {}\\r\\nContent-Length: {}\\r\\nCache-Control: no-store\\r\\nX-Content-Type-Options: nosniff\\r\\nReferrer-Policy: no-referrer\\r\\nX-Frame-Options: DENY\\r\\nCross-Origin-Opener-Policy: same-origin\\r\\nCross-Origin-Resource-Policy: same-origin\\r\\nX-Permitted-Cross-Domain-Policies: none\\r\\nPermissions-Policy: camera=(), microphone=(), geolocation=()\\r\\nContent-Security-Policy: default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self' ws: wss:\\r\\nConnection: close\\r\\n\\r\\n", r.status, reason, r.ctype, r.body.len())
}

fn write_response(mut s: &TcpStream, r: &Resp) {
    let head = response_head(r);
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(r.body.as_bytes());
}

fn route(sh: &Shared, req: &Req) -> Resp {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => Resp { status: 200, ctype: "text/html; charset=utf-8", body: INDEX_HTML.to_string() },
        ("GET", "/healthz") => json(200, "{\"ok\":true}".into()),
        ("GET", "/api/online") => json(200, format!("{{\"n\":{}}}", sh.lock().online())),
        _ => err_resp(404, "не найдено"),
    }
}

type Writer = Arc<Mutex<TcpStream>>;

fn send_frame(w: &Writer, opcode: u8, payload: &[u8]) -> bool {
    let mut g = w.lock().unwrap_or_else(|e| e.into_inner());
    ws::write_frame(&mut *g, opcode, payload).is_ok()
}

fn send_err(w: &Writer, msg: &str) {
    send_frame(w, 1, format!("{{\"t\":\"err\",\"m\":{}}}", json_str(msg)).as_bytes());
}

/// Команды клиента: поля разделены табуляцией.
///   find/random \t тема \t свой_пол \t кого_ищем \t свой_возраст \t возрасты_через_запятую
///   msg \t текст | typing | leave | report | ping
fn handle_cmd(sh: &Shared, w: &Writer, id: &str, text: &str) {
    let now = Instant::now();
    let mut p = text.splitn(2, '\t');
    let cmd = p.next().unwrap_or("");
    let rest = p.next().unwrap_or("");
    let r = {
        let mut st = sh.lock();
        match cmd {
            "ping" => {
                st.touch(id, now);
                Ok(())
            }
            "find" | "random" => {
                let random = cmd == "random";
                let f: Vec<&str> = rest.split('\t').collect();
                if f.len() != 5 {
                    Err((400, "неверный запрос"))
                } else {
                    Prefs::parse(f[0], f[1], f[2], f[3], f[4]).and_then(|pf| {
                        if random { st.find_random(id, now, pf) } else { st.find(id, now, pf) }
                    })
                }
            }
            "msg" => st.send(id, rest, now),
            "typing" => st.typing(id, now),
            "leave" => st.leave(id, now),
            "report" => st.report(id, now).map(|_| ()),
            _ => Err((400, "неизвестная команда")),
        }
    };
    sh.cv.notify_all();
    if let Err((_, m)) = r {
        send_err(w, m);
    }
}

/// Поток-писатель: отправляет события клиенту и шлёт пульс, когда тихо.
fn writer_loop(sh: Arc<Shared>, w: Writer, id: String, done: Arc<AtomicBool>) {
    // Не даём клиентским ping/командам сбрасывать таймер heartbeat:
    // Condvar может просыпаться сколько угодно раз, срок следующего пульса фиксирован.
    let mut next_beat = Instant::now() + HEARTBEAT;
    loop {
        let (events, beat) = {
            let mut g = sh.lock();
            loop {
                if done.load(Ordering::SeqCst) {
                    return;
                }
                match g.take_events(&id) {
                    None => return,
                    Some(v) if !v.is_empty() => break (v, false),
                    _ => {}
                }
                let now = Instant::now();
                if now >= next_beat {
                    next_beat = now + HEARTBEAT;
                    break (Vec::new(), true);
                }
                let wait = next_beat.saturating_duration_since(now);
                let (ng, _) = sh.cv.wait_timeout(g, wait).unwrap_or_else(|e| e.into_inner());
                g = ng;
            }
        };
        for e in events {
            if !send_frame(&w, 1, e.as_bytes()) {
                done.store(true, Ordering::SeqCst);
                let g = w.lock().unwrap_or_else(|e| e.into_inner());
                let _ = g.shutdown(Shutdown::Both);
                sh.cv.notify_all();
                return;
            }
        }
        if beat && !(send_frame(&w, 9, b"") && send_frame(&w, 1, b"{\"t\":\"hb\"}")) {
            done.store(true, Ordering::SeqCst);
            let g = w.lock().unwrap_or_else(|e| e.into_inner());
            let _ = g.shutdown(Shutdown::Both);
            sh.cv.notify_all();
            return;
        }
    }
}

fn ws_session(sh: Arc<Shared>, stream: TcpStream, ip: IpAddr, key: &str) {
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        ws::accept_key(key)
    );
    if (&stream).write_all(resp.as_bytes()).is_err() {
        return;
    }
    let _ = stream.set_read_timeout(Some(WS_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_nodelay(true);
    let Ok(wclone) = stream.try_clone() else { return };
    let w: Writer = Arc::new(Mutex::new(wclone));

    let id = new_id();
    if let Err((_, m)) = sh.lock().join(ip, Instant::now(), id.clone()) {
        send_err(&w, m);
        send_frame(&w, 8, b"");
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    sh.cv.notify_all();

    let done = Arc::new(AtomicBool::new(false));
    {
        let (sh2, w2, id2, d2) = (Arc::clone(&sh), Arc::clone(&w), id.clone(), Arc::clone(&done));
        std::thread::spawn(move || writer_loop(sh2, w2, id2, d2));
    }

    let mut reader = &stream;
    loop {
        match ws::read_frame(&mut reader, MAX_FRAME) {
            Ok(Frame::Text(t)) => handle_cmd(&sh, &w, &id, &t),
            Ok(Frame::Ping(p)) => {
                sh.lock().touch(&id, Instant::now());
                send_frame(&w, 10, &p);
            }
            Ok(Frame::Pong) => {
                sh.lock().touch(&id, Instant::now());
            }
            Ok(Frame::Close) | Err(_) => break,
        }
    }
    // Соединение закрыто: убираем сессию, собеседник узнаёт об этом сразу.
    done.store(true, Ordering::SeqCst);
    sh.lock().remove(&id);
    sh.cv.notify_all();
    send_frame(&w, 8, b"");
    let _ = stream.shutdown(Shutdown::Both);
}

fn valid_ws_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    bytes.len() == 24
        && bytes[22..] == *b"=="
        && bytes[..22].iter().all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
}

fn handle(sh: Arc<Shared>, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let peer = match stream.peer_addr() {
        Ok(a) => a.ip(),
        Err(_) => return,
    };
    let Some(req) = read_request(&stream, peer) else {
        write_response(&stream, &err_resp(400, "плохой запрос"));
        return;
    };
    if req.path == "/ws" {
        if req.method != "GET" || !req.upgrade_ws || !req.connection_upgrade || !req.ws_version_13 {
            write_response(&stream, &err_resp(400, "неверное рукопожатие WebSocket"));
            return;
        }
        if !origin_ok(req.origin.as_deref(), req.host.as_deref()) {
            write_response(&stream, &err_resp(403, "чужой источник"));
            return;
        }
        match req.ws_key.as_deref() {
            Some(k) if valid_ws_key(k) => ws_session(sh, stream, req.ip, k),
            _ => write_response(&stream, &err_resp(400, "нет ключа WebSocket")),
        }
        return;
    }
    write_response(&stream, &route(&sh, &req));
}

fn main() {
    // Хостинги задают порт через PORT и ждут адрес 0.0.0.0.
    let addr = std::env::var("CHAT_ADDR").unwrap_or_else(|_| match std::env::var("PORT") {
        Ok(p) => format!("0.0.0.0:{p}"),
        Err(_) => "127.0.0.1:8080".into(),
    });
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("не удалось занять {addr}: {e}");
        std::process::exit(1);
    });
    let shared = Arc::new(Shared { state: Mutex::new(State::new()), cv: Condvar::new() });

    let reaper = Arc::clone(&shared);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        reaper.lock().reap(Instant::now());
        reaper.cv.notify_all();
    });

    let active = Arc::new(AtomicUsize::new(0));
    println!("anon-chat слушает http://{addr}");
    for stream in listener.incoming().flatten() {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            write_response(&stream, &err_resp(429, "сервер перегружен"));
            continue;
        }
        let (sh, act) = (Arc::clone(&shared), Arc::clone(&active));
        std::thread::spawn(move || {
            handle(sh, stream);
            act.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_uses_trusted_hops_only() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let real: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(client_ip(peer, Some("9.9.9.9"), 0), peer);
        assert_eq!(client_ip(peer, Some("1.2.3.4"), 1), real);
        assert_eq!(client_ip(peer, Some("6.6.6.6, 1.2.3.4"), 1), real);
        assert_eq!(client_ip(peer, Some("1.2.3.4, 10.1.1.1"), 2), real);
        assert_eq!(client_ip(peer, None, 1), peer);
        assert_eq!(client_ip(peer, Some("мусор"), 1), peer);
        assert_eq!(client_ip(peer, Some("1.2.3.4"), 3), peer);
    }

    #[test]
    fn origin_must_match_host() {
        assert!(origin_ok(None, Some("chat.example")));
        assert!(origin_ok(Some("https://chat.example"), Some("chat.example")));
        assert!(origin_ok(Some("http://127.0.0.1:8080"), Some("127.0.0.1:8080")));
        assert!(!origin_ok(Some("https://evil.example"), Some("chat.example")));
        assert!(!origin_ok(Some("https://chat.example.evil.com"), Some("chat.example")));
        assert!(!origin_ok(Some("https://chat.example"), None));
        assert!(!origin_ok(Some("null"), Some("chat.example")));
        assert!(!origin_ok(Some("ftp://chat.example"), Some("chat.example")));
        assert!(!origin_ok(Some("javascript://chat.example"), Some("chat.example")));
    }

    fn parse_test_request(raw: &str) -> Option<Req> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.write_all(raw.as_bytes()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let (server, _) = listener.accept().unwrap();
        read_request(&server, "127.0.0.1".parse().unwrap())
    }

    #[test]
    fn http_parser_accepts_only_well_formed_http11_origin_form() {
        let req = parse_test_request("GET /healthz?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        assert_eq!(req.path, "/healthz");
        assert_eq!(req.host.as_deref(), Some("localhost"));
        assert!(parse_test_request("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").is_none());
        assert!(parse_test_request("GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n").is_none());
        assert!(parse_test_request("GET / HTTP/1.1\r\nHost: localhost\r\nHost: evil\r\n\r\n").is_none());
        assert!(parse_test_request("GET / HTTP/1.1\r\nHost: localhost\r\nMalformed\r\n\r\n").is_none());
        assert!(parse_test_request("GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn http_parser_caps_header_count_and_line_length() {
        let mut many = String::from("GET / HTTP/1.1\r\nHost: localhost\r\n");
        for i in 0..70 { many.push_str(&format!("X-Test-{i}: x\r\n")); }
        many.push_str("\r\n");
        assert!(parse_test_request(&many).is_none());
        let long = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n", "x".repeat(9000));
        assert!(parse_test_request(&long).is_none());
    }
    #[test]
    fn response_headers_are_well_formed_and_hardened() {
        let head = response_head(&Resp { status: 200, ctype: "text/plain", body: "ok".into() });
        assert!(head.starts_with("HTTP/1.1 200 OK\\r\\n"));
        assert!(head.ends_with("\\r\\n\\r\\n"));
        assert!(head.contains("frame-ancestors 'none'"));
        assert!(head.contains("X-Frame-Options: DENY"));
        assert!(head.contains("Permissions-Policy: camera=(), microphone=(), geolocation=()"));
    }

}
