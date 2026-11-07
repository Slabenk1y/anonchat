//! Чистая логика чата без сети: очередь, подбор пары, лимиты, жалобы и баны.
//! Время и идентификаторы передаются снаружи, поэтому всё легко тестируется.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const MAX_MSG_CHARS: usize = 500;
pub const RATE_WINDOW: Duration = Duration::from_secs(3);
pub const RATE_MAX: usize = 5;
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const REPORTS_TO_BAN: usize = 3;
pub const BAN_DURATION: Duration = Duration::from_secs(3600);
pub const MAX_SESSIONS_PER_IP: usize = 5;
const MAX_QUEUED_EVENTS: usize = 200;

pub type Err = (u16, &'static str);

pub struct User {
    ip: IpAddr,
    partner: Option<String>,
    /// Последний собеседник (id, ip): нужен, чтобы пожаловаться после завершения чата.
    last_partner: Option<(String, IpAddr)>,
    events: VecDeque<String>,
    last_seen: Instant,
    sent: VecDeque<Instant>,
    waiting: bool,
}

#[derive(Default)]
pub struct State {
    users: HashMap<String, User>,
    queue: VecDeque<String>,
    bans: HashMap<IpAddr, Instant>,
    report_log: HashMap<IpAddr, HashSet<IpAddr>>,
}

pub fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn ev(t: &str) -> String {
    format!("{{\"t\":{}}}", json_str(t))
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    fn is_banned(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.bans.get(&ip) {
            Some(&until) if until > now => true,
            Some(_) => {
                self.bans.remove(&ip);
                false
            }
            None => false,
        }
    }

    fn push(&mut self, id: &str, e: String) {
        if let Some(u) = self.users.get_mut(id) {
            if u.events.len() >= MAX_QUEUED_EVENTS {
                u.events.pop_front();
            }
            u.events.push_back(e);
        }
    }

    pub fn join(&mut self, ip: IpAddr, now: Instant, id: String) -> Result<String, Err> {
        if self.is_banned(ip, now) {
            return Err((403, "вы заблокированы"));
        }
        if self.users.values().filter(|u| u.ip == ip).count() >= MAX_SESSIONS_PER_IP {
            return Err((429, "слишком много сессий"));
        }
        self.users.insert(
            id.clone(),
            User {
                ip,
                partner: None,
                last_partner: None,
                events: VecDeque::new(),
                last_seen: now,
                sent: VecDeque::new(),
                waiting: false,
            },
        );
        Ok(id)
    }

    fn pair(&mut self, a: &str, b: &str) {
        let a_ip = self.users[a].ip;
        let b_ip = self.users[b].ip;
        for (me, other, other_ip) in [(a, b, b_ip), (b, a, a_ip)] {
            if let Some(u) = self.users.get_mut(me) {
                u.partner = Some(other.to_string());
                u.last_partner = Some((other.to_string(), other_ip));
                u.waiting = false;
            }
            self.push(me, ev("matched"));
        }
    }

    pub fn find(&mut self, id: &str, now: Instant) -> Result<(), Err> {
        let ip = {
            let u = self.users.get_mut(id).ok_or((404, "нет сессии"))?;
            u.last_seen = now;
            if u.partner.is_some() {
                return Err((409, "вы уже в чате"));
            }
            if u.waiting {
                return Ok(());
            }
            u.ip
        };
        if self.is_banned(ip, now) {
            return Err((403, "вы заблокированы"));
        }
        let my_last = self.users[id].last_partner.as_ref().map(|p| p.0.clone());
        let pos = self.queue.iter().position(|c| {
            c != id
                && Some(c) != my_last.as_ref()
                && self.users.get(c).map_or(false, |cu| {
                    cu.waiting
                        && cu.partner.is_none()
                        && cu.last_partner.as_ref().map(|p| p.0.as_str()) != Some(id)
                })
        });
        match pos {
            Some(p) => {
                let c = self.queue.remove(p).unwrap();
                self.pair(id, &c);
            }
            None => {
                self.users.get_mut(id).unwrap().waiting = true;
                self.queue.push_back(id.to_string());
                self.push(id, ev("waiting"));
            }
        }
        Ok(())
    }

    fn end_chat(&mut self, id: &str) {
        self.queue.retain(|q| q != id);
        let partner = match self.users.get_mut(id) {
            Some(u) => {
                u.waiting = false;
                u.partner.take()
            }
            None => return,
        };
        if let Some(p) = partner {
            if let Some(pu) = self.users.get_mut(&p) {
                pu.partner = None;
            }
            self.push(&p, ev("left"));
        }
    }

    pub fn leave(&mut self, id: &str, now: Instant) -> Result<(), Err> {
        self.users.get_mut(id).ok_or((404, "нет сессии"))?.last_seen = now;
        self.end_chat(id);
        Ok(())
    }

    pub fn send(&mut self, id: &str, text: &str, now: Instant) -> Result<(), Err> {
        let ip = {
            let u = self.users.get_mut(id).ok_or((404, "нет сессии"))?;
            u.last_seen = now;
            u.ip
        };
        if self.is_banned(ip, now) {
            return Err((403, "вы заблокированы"));
        }
        let text = text.trim();
        if text.is_empty() {
            return Err((400, "пустое сообщение"));
        }
        if text.chars().count() > MAX_MSG_CHARS {
            return Err((413, "сообщение слишком длинное"));
        }
        if text.chars().any(|c| c.is_control() && c != '\n') {
            return Err((400, "недопустимые символы"));
        }
        let partner = {
            let u = self.users.get_mut(id).unwrap();
            while u.sent.front().map_or(false, |t| now.duration_since(*t) > RATE_WINDOW) {
                u.sent.pop_front();
            }
            if u.sent.len() >= RATE_MAX {
                return Err((429, "слишком часто"));
            }
            u.sent.push_back(now);
            u.partner.clone().ok_or((409, "нет собеседника"))?
        };
        self.push(
            &partner,
            format!("{{\"t\":\"msg\",\"text\":{}}}", json_str(text)),
        );
        Ok(())
    }

    pub fn typing(&mut self, id: &str, now: Instant) -> Result<(), Err> {
        let u = self.users.get_mut(id).ok_or((404, "нет сессии"))?;
        u.last_seen = now;
        if let Some(p) = u.partner.clone() {
            let dup = self
                .users
                .get(&p)
                .and_then(|x| x.events.back())
                .map_or(false, |e| e == &ev("typing"));
            if !dup {
                self.push(&p, ev("typing"));
            }
        }
        Ok(())
    }

    /// Жалоба на последнего собеседника. Возвращает true, если он получил бан.
    pub fn report(&mut self, id: &str, now: Instant) -> Result<bool, Err> {
        let (reporter_ip, target) = {
            let u = self.users.get_mut(id).ok_or((404, "нет сессии"))?;
            u.last_seen = now;
            (u.ip, u.last_partner.clone().ok_or((409, "некого репортить"))?)
        };
        let target_ip = target.1;
        if target_ip == reporter_ip {
            return Ok(false);
        }
        let set = self.report_log.entry(target_ip).or_default();
        set.insert(reporter_ip);
        if set.len() < REPORTS_TO_BAN {
            return Ok(false);
        }
        self.report_log.remove(&target_ip);
        self.bans.insert(target_ip, now + BAN_DURATION);
        let ids: Vec<String> = self
            .users
            .iter()
            .filter(|(_, u)| u.ip == target_ip)
            .map(|(k, _)| k.clone())
            .collect();
        for i in ids {
            self.end_chat(&i);
            self.push(&i, ev("banned"));
        }
        Ok(true)
    }

    /// None — сессии нет (клиент должен зайти заново).
    pub fn take_events(&mut self, id: &str, now: Instant) -> Option<Vec<String>> {
        self.users.get_mut(id).map(|u| {
            u.last_seen = now;
            u.events.drain(..).collect()
        })
    }

    pub fn reap(&mut self, now: Instant) {
        let dead: Vec<String> = self
            .users
            .iter()
            .filter(|(_, u)| now.duration_since(u.last_seen) > IDLE_TIMEOUT)
            .map(|(k, _)| k.clone())
            .collect();
        for id in dead {
            self.end_chat(&id);
            self.users.remove(&id);
        }
        self.bans.retain(|_, until| *until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    fn two(s: &mut State, now: Instant) {
        s.join(ip(1), now, "a".into()).unwrap();
        s.join(ip(2), now, "b".into()).unwrap();
        s.find("a", now).unwrap();
        s.find("b", now).unwrap();
    }

    #[test]
    fn pairs_two_users_and_relays_messages() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        assert_eq!(s.take_events("a", now).unwrap(), vec![ev("waiting"), ev("matched")]);
        assert_eq!(s.take_events("b", now).unwrap(), vec![ev("matched")]);
        s.send("a", "привет \"мир\"", now).unwrap();
        assert_eq!(
            s.take_events("b", now).unwrap(),
            vec!["{\"t\":\"msg\",\"text\":\"привет \\\"мир\\\"\"}".to_string()]
        );
    }

    #[test]
    fn leave_notifies_partner_and_blocks_sending() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        s.take_events("a", now);
        s.take_events("b", now);
        s.leave("a", now).unwrap();
        assert_eq!(s.take_events("b", now).unwrap(), vec![ev("left")]);
        assert_eq!(s.send("b", "эй", now), Err((409, "нет собеседника")));
    }

    #[test]
    fn no_immediate_rematch_with_previous_partner() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        s.leave("a", now).unwrap();
        s.find("a", now).unwrap();
        s.find("b", now).unwrap();
        // оба ждут и не должны снова попасть друг к другу
        assert!(s.users["a"].waiting && s.users["b"].waiting);
        s.join(ip(3), now, "c".into()).unwrap();
        s.find("c", now).unwrap();
        assert!(s.users["c"].partner.is_some());
    }

    #[test]
    fn validates_messages_and_rate_limits() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        assert_eq!(s.send("a", "   ", now), Err((400, "пустое сообщение")));
        assert_eq!(s.send("a", &"я".repeat(501), now), Err((413, "сообщение слишком длинное")));
        assert_eq!(s.send("a", "a\u{0007}b", now), Err((400, "недопустимые символы")));
        for _ in 0..RATE_MAX {
            s.send("a", "x", now).unwrap();
        }
        assert_eq!(s.send("a", "x", now), Err((429, "слишком часто")));
        s.send("a", "x", now + RATE_WINDOW + Duration::from_millis(1)).unwrap();
    }

    #[test]
    fn three_distinct_reporters_ban_the_ip() {
        let (mut s, now) = (State::new(), Instant::now());
        s.join(ip(9), now, "bad".into()).unwrap();
        for (i, name) in [(1u8, "r1"), (2, "r2"), (3, "r3")] {
            s.join(ip(i), now, name.into()).unwrap();
            s.find("bad", now).unwrap();
            s.find(name, now).unwrap();
            let banned = s.report(name, now).unwrap();
            assert_eq!(banned, i == 3);
            if i < 3 {
                s.leave(name, now).unwrap();
                s.leave("bad", now).unwrap();
                // чтобы не работала защита от повторного матча
                s.users.get_mut("bad").unwrap().last_partner = None;
            }
        }
        assert_eq!(s.find("bad", now), Err((403, "вы заблокированы")));
        assert_eq!(s.join(ip(9), now, "new".into()), Err((403, "вы заблокированы")));
        // бан истекает
        s.join(ip(9), now + BAN_DURATION + Duration::from_secs(1), "new".into()).unwrap();
    }

    #[test]
    fn same_reporter_counts_once_and_self_report_ignored() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        for _ in 0..5 {
            assert_eq!(s.report("a", now), Ok(false));
        }
        assert!(s.bans.is_empty());
    }

    #[test]
    fn reaper_removes_idle_and_frees_partner() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        s.take_events("b", now);
        let later = now + IDLE_TIMEOUT + Duration::from_secs(1);
        s.take_events("b", later); // b «жив», a — нет
        s.reap(later);
        assert!(s.users.get("a").is_none());
        assert_eq!(s.take_events("b", later).unwrap(), vec![ev("left")]);
    }

    #[test]
    fn session_limit_per_ip() {
        let (mut s, now) = (State::new(), Instant::now());
        for i in 0..MAX_SESSIONS_PER_IP {
            s.join(ip(1), now, format!("u{i}")).unwrap();
        }
        assert_eq!(s.join(ip(1), now, "x".into()), Err((429, "слишком много сессий")));
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_str("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
    }
}
