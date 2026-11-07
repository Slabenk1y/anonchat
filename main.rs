//! Анонимный текстовый чат: HTTP-сервер на чистом std (без внешних крейтов).
//! События доставляются long-poll'ом, отправка — обычными POST.

mod state;

use state::{json_str, Err, State};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const INDEX_HTML: &str = include_str!("index.html");
const POLL_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_BODY: usize = 4096;
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
    query: String,
    body: String,
    ip: IpAddr,
}

struct Resp {
    status: u16,
    ctype: &'static str,
    body: String,
}

fn json(status: u16, body: String) -> Resp {
    Resp { status, ctype: "application/json; charset=utf-8", body }
}

fn err_resp((code, msg): Err) -> Resp {
    json(code, format!("{{\"error\":{}}}", json_str(msg)))
}

/// Случайный 128-битный токен. RandomState берёт ключи у ОС.
/// Для продакшена лучше заменить на getrandom/OsRng.
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

fn query_id(q: &str) -> Option<&str> {
    q.split('&')
        .find_map(|kv| kv.strip_prefix("id="))
        .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
}

const LANGS: [&str; 2] = ["ru", "en"];
const TAGS: [&str; 11] = [
    "talk", "music", "games", "movies", "anime", "sport", "tech", "books", "travel", "memes", "study",
];

fn query_param<'a>(q: &'a str, key: &str) -> Option<&'a str> {
    q.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))
}

/// Язык и интересы из запроса. Принимаются только значения из белого списка, не больше трёх интересов.
fn parse_filters(q: &str) -> (String, Vec<String>) {
    let lang = query_param(q, "lang").filter(|l| LANGS.contains(l)).unwrap_or("ru").to_string();
    let mut tags: Vec<String> = Vec::new();
    for t in query_param(q, "tags").unwrap_or("").split(',') {
        if TAGS.contains(&t) && !tags.iter().any(|x| x == t) && tags.len() < 3 {
            tags.push(t.to_string());
        }
    }
    (lang, tags)
}

fn route(sh: &Shared, req: &Req) -> Resp {
    let now = Instant::now();
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => Resp { status: 200, ctype: "text/html; charset=utf-8", body: INDEX_HTML.to_string() },
        ("GET", "/healthz") => json(200, "{\"ok\":true}".into()),
        ("POST", "/api/join") => {
            let r = sh.lock().join(req.ip, now, new_id());
            match r {
                Ok(id) => json(200, format!("{{\"id\":\"{id}\"}}")),
                Err(e) => err_resp(e),
            }
        }
        ("GET", "/api/events") => match query_id(&req.query) {
            Some(id) => long_poll(sh, id),
            None => err_resp((400, "неверный id")),
        },
        ("POST", p @ ("/api/find" | "/api/leave" | "/api/send" | "/api/typing" | "/api/report")) => {
            let Some(id) = query_id(&req.query) else {
                return err_resp((400, "неверный id"));
            };
            let r = {
                let mut st = sh.lock();
                match p {
                    "/api/find" => {
                        let (lang, tags) = parse_filters(&req.query);
                        st.find(id, now, &lang, &tags)
                    }
                    .map(|_| "{\"ok\":true}".to_string()),
                    "/api/leave" => st.leave(id, now).map(|_| "{\"ok\":true}".to_string()),
                    "/api/send" => st.send(id, &req.body, now).map(|_| "{\"ok\":true}".to_string()),
                    "/api/typing" => st.typing(id, now).map(|_| "{\"ok\":true}".to_string()),
                    _ => st.report(id, now).map(|b| format!("{{\"ok\":true,\"banned\":{b}}}")),
                }
            };
            sh.cv.notify_all();
            match r {
                Ok(b) => json(200, b),
                Err(e) => err_resp(e),
            }
        }
        _ => err_resp((404, "не найдено")),
    }
}

fn long_poll(sh: &Shared, id: &str) -> Resp {
    let deadline = Instant::now() + POLL_TIMEOUT;
    let mut g = sh.lock();
    loop {
        let now = Instant::now();
        match g.take_events(id, now) {
            None => return err_resp((404, "нет сессии")),
            Some(v) if !v.is_empty() => return json(200, format!("[{}]", v.join(","))),
            _ => {}
        }
        if now >= deadline {
            return json(200, "[]".into());
        }
        g = sh
            .cv
            .wait_timeout(g, deadline - now)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
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

fn read_request(stream: &TcpStream, ip: IpAddr) -> Option<Req> {
    let mut rd = BufReader::new(stream.take(16 * 1024));
    let mut line = String::new();
    rd.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut len = 0usize;
    let mut xff: Option<String> = None;
    loop {
        let mut h = String::new();
        if rd.read_line(&mut h).ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().ok()?;
            } else if k.eq_ignore_ascii_case("x-forwarded-for") {
                xff = Some(v.trim().to_string());
            }
        }
    }
    if len > MAX_BODY {
        return None;
    }
    let mut body = vec![0u8; len];
    rd.read_exact(&mut body).ok()?;
    let ip = client_ip(ip, xff.as_deref(), proxy_hops());
    Some(Req { method, path, query, body: String::from_utf8(body).ok()?, ip })
}

fn write_response(mut s: &TcpStream, r: &Resp) {
    let reason = match r.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'\r\n\
         Connection: close\r\n\r\n",
        r.status,
        reason,
        r.ctype,
        r.body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(r.body.as_bytes());
}

fn handle(sh: &Shared, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let ip = match stream.peer_addr() {
        Ok(a) => a.ip(),
        Err(_) => return,
    };
    let resp = match read_request(&stream, ip) {
        Some(req) => route(sh, &req),
        None => err_resp((400, "плохой запрос")),
    };
    write_response(&stream, &resp);
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
            write_response(&stream, &err_resp((429, "сервер перегружен")));
            continue;
        }
        let (sh, act) = (Arc::clone(&shared), Arc::clone(&active));
        std::thread::spawn(move || {
            handle(&sh, stream);
            act.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_are_whitelisted() {
        let (l, t) = parse_filters("id=x&lang=en&tags=music,evil,games,music,anime,sport");
        assert_eq!(l, "en");
        assert_eq!(t, vec!["music", "games", "anime"]);
        assert_eq!(parse_filters("id=x&lang=zz").0, "ru");
    }

    #[test]
    fn client_ip_uses_trusted_hops_only() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let real: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(client_ip(peer, Some("9.9.9.9"), 0), peer);
        assert_eq!(client_ip(peer, Some("1.2.3.4"), 1), real);
        // клиент подделал левое значение, прокси дописал настоящее справа
        assert_eq!(client_ip(peer, Some("6.6.6.6, 1.2.3.4"), 1), real);
        assert_eq!(client_ip(peer, Some("1.2.3.4, 10.1.1.1"), 2), real);
        assert_eq!(client_ip(peer, None, 1), peer);
        assert_eq!(client_ip(peer, Some("мусор"), 1), peer);
        assert_eq!(client_ip(peer, Some("1.2.3.4"), 3), peer);
    }
}
