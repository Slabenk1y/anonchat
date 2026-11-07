//! Чистая логика чата без сети: очередь, подбор пары, лимиты, жалобы и баны.
//! Время и идентификаторы передаются снаружи, поэтому всё легко тестируется.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const MAX_MSG_CHARS: usize = 500;
pub const RATE_WINDOW: Duration = Duration::from_secs(3);
pub const RATE_MAX: usize = 5;
/// Если от клиента не было ни одного кадра (пинг идёт каждые 15 с), сессия считается мёртвой.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// В пару берём только тех, кто подавал признаки жизни совсем недавно.
pub const FRESH_FOR_MATCH: Duration = Duration::from_secs(25);
pub const REPORTS_TO_BAN: usize = 3;
pub const BAN_DURATION: Duration = Duration::from_secs(3600);
pub const MAX_SESSIONS_PER_IP: usize = 5;
const MAX_QUEUED_EVENTS: usize = 200;

pub const TOPICS: [&str; 3] = ["chat", "flirt", "rp"];
pub const CHAT_AGES: [&str; 5] = ["u17", "a18_21", "a22_25", "a26_35", "a36"];
pub const ADULT_AGES: [&str; 3] = ["a18_25", "a26_35", "a36"];

pub type Err = (u16, &'static str);

/// Параметры поиска одного человека.
#[derive(Clone, Debug, PartialEq)]
pub struct Prefs {
    pub topic: String,
    /// Свой пол: x (не указан), m, f.
    pub gender: String,
    /// Кого ищем: any, m, f.
    pub seek: String,
    pub age: String,
    /// Допустимые возрасты собеседника; пусто — любой допустимый.
    pub ages: Vec<String>,
}

impl Prefs {
    pub fn parse(topic: &str, gender: &str, seek: &str, age: &str, ages_csv: &str) -> Result<Prefs, Err> {
        if !TOPICS.contains(&topic) {
            return Err((400, "неизвестная тема"));
        }
        let allowed: &[&str] = if topic == "chat" { &CHAT_AGES } else { &ADULT_AGES };
        if !allowed.contains(&age) {
            return Err((400, "выберите свой возраст"));
        }
        if !["x", "m", "f"].contains(&gender) || !["any", "m", "f"].contains(&seek) {
            return Err((400, "неверный пол"));
        }
        let mut ages: Vec<String> = Vec::new();
        for a in ages_csv.split(',').filter(|a| !a.is_empty()) {
            if !allowed.contains(&a) {
                return Err((400, "неверный возраст собеседника"));
            }
            if !ages.iter().any(|x| x == a) {
                ages.push(a.to_string());
            }
        }
        if age == "u17" {
            // Несовершеннолетние общаются только друг с другом.
            ages = vec!["u17".to_string()];
        } else {
            let had = !ages.is_empty();
            ages.retain(|a| a != "u17");
            if had && ages.is_empty() {
                return Err((400, "выберите возраст собеседника"));
            }
        }
        Ok(Prefs {
            topic: topic.into(),
            gender: gender.into(),
            seek: seek.into(),
            age: age.into(),
            ages,
        })
    }

    fn is_minor(&self) -> bool {
        self.age == "u17"
    }
}

/// Взаимная совместимость: тема, пол и возраст должны устраивать обе стороны.
/// Жёсткое правило безопасности: до 17 лет и взрослые никогда не соединяются.
pub fn compatible(a: &Prefs, b: &Prefs) -> bool {
    a.topic == b.topic
        && a.is_minor() == b.is_minor()
        && (a.seek == "any" || a.seek == b.gender)
        && (b.seek == "any" || b.seek == a.gender)
        && (a.ages.is_empty() || a.ages.contains(&b.age))
        && (b.ages.is_empty() || b.ages.contains(&a.age))
}

pub struct User {
    ip: IpAddr,
    partner: Option<String>,
    /// Последний собеседник (id, ip): нужен, чтобы пожаловаться после завершения чата.
    last_partner: Option<(String, IpAddr)>,
    events: VecDeque<String>,
    last_seen: Instant,
    sent: VecDeque<Instant>,
    waiting: bool,
    prefs: Option<Prefs>,
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

    /// Сколько человек сейчас в чате или в поиске.
    pub fn online(&self) -> usize {
        self.users.len()
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
                prefs: None,
            },
        );
        Ok(id)
    }

    /// Любой входящий кадр от клиента (в том числе пинг) продлевает жизнь сессии.
    pub fn touch(&mut self, id: &str, now: Instant) -> bool {
        match self.users.get_mut(id) {
            Some(u) => {
                u.last_seen = now;
                true
            }
            None => false,
        }
    }

    fn pair(&mut self, a: &str, b: &str) {
        let info = |s: &State, id: &str| {
            let u = &s.users[id];
            let p = u.prefs.as_ref().unwrap();
            (u.ip, p.gender.clone(), p.age.clone())
        };
        let (a_ip, a_g, a_a) = info(self, a);
        let (b_ip, b_g, b_a) = info(self, b);
        for (me, other, other_ip, og, oa) in [(a, b, b_ip, b_g, b_a), (b, a, a_ip, a_g, a_a)] {
            if let Some(u) = self.users.get_mut(me) {
                u.partner = Some(other.to_string());
                u.last_partner = Some((other.to_string(), other_ip));
                u.waiting = false;
            }
            self.push(me, format!("{{\"t\":\"matched\",\"g\":\"{og}\",\"a\":\"{oa}\"}}"));
        }
    }

    pub fn find(&mut self, id: &str, now: Instant, prefs: Prefs) -> Result<(), Err> {
        let ip = {
            let u = self.users.get_mut(id).ok_or((404, "нет сессии"))?;
            u.last_seen = now;
            if u.partner.is_some() {
                return Err((409, "вы уже в чате"));
            }
            if u.waiting {
                // Уже ищем: просто обновим параметры, место в очереди сохраняется.
                u.prefs = Some(prefs);
                return Ok(());
            }
            u.prefs = Some(prefs.clone());
            u.ip
        };
        if self.is_banned(ip, now) {
            return Err((403, "вы заблокированы"));
        }
        let my_last = self.users[id].last_partner.as_ref().map(|p| p.0.clone());
        let pos = self.queue.iter().position(|c| {
            if c == id || Some(c) == my_last.as_ref() {
                return false;
            }
            let Some(cu) = self.users.get(c) else { return false };
            cu.waiting
                && cu.partner.is_none()
                && now.duration_since(cu.last_seen) < FRESH_FOR_MATCH
                && cu.last_partner.as_ref().map(|p| p.0.as_str()) != Some(id)
                && cu.prefs.as_ref().map_or(false, |cp| compatible(&prefs, cp))
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

    /// Соединение закрыто: собеседник узнаёт об этом сразу.
    pub fn remove(&mut self, id: &str) {
        self.end_chat(id);
        self.users.remove(id);
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
        self.push(&partner, format!("{{\"t\":\"msg\",\"text\":{}}}", json_str(text)));
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

    /// Забирает накопленные события. None — сессии больше нет.
    /// Жизнь сессии это не продлевает: её подтверждают только входящие кадры клиента.
    pub fn take_events(&mut self, id: &str) -> Option<Vec<String>> {
        self.users.get_mut(id).map(|u| u.events.drain(..).collect())
    }

    pub fn reap(&mut self, now: Instant) {
        let dead: Vec<String> = self
            .users
            .iter()
            .filter(|(_, u)| now.duration_since(u.last_seen) > IDLE_TIMEOUT)
            .map(|(k, _)| k.clone())
            .collect();
        for id in dead {
            self.remove(&id);
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

    fn pf(topic: &str, gender: &str, seek: &str, age: &str, ages: &str) -> Prefs {
        Prefs::parse(topic, gender, seek, age, ages).unwrap()
    }

    fn any() -> Prefs {
        pf("chat", "x", "any", "a22_25", "")
    }

    fn matched(g: &str, a: &str) -> String {
        format!("{{\"t\":\"matched\",\"g\":\"{g}\",\"a\":\"{a}\"}}")
    }

    fn two(s: &mut State, now: Instant) {
        s.join(ip(1), now, "a".into()).unwrap();
        s.join(ip(2), now, "b".into()).unwrap();
        s.find("a", now, any()).unwrap();
        s.find("b", now, any()).unwrap();
    }

    #[test]
    fn pairs_two_users_and_relays_messages() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        assert_eq!(s.take_events("a").unwrap(), vec![ev("waiting"), matched("x", "a22_25")]);
        assert_eq!(s.take_events("b").unwrap(), vec![matched("x", "a22_25")]);
        s.send("a", "привет \"мир\"", now).unwrap();
        assert_eq!(
            s.take_events("b").unwrap(),
            vec!["{\"t\":\"msg\",\"text\":\"привет \\\"мир\\\"\"}".to_string()]
        );
    }

    #[test]
    fn matched_event_describes_the_partner() {
        let (mut s, now) = (State::new(), Instant::now());
        s.join(ip(1), now, "a".into()).unwrap();
        s.join(ip(2), now, "b".into()).unwrap();
        s.find("a", now, pf("chat", "f", "any", "a18_21", "")).unwrap();
        s.find("b", now, pf("chat", "m", "any", "a26_35", "")).unwrap();
        assert_eq!(s.take_events("a").unwrap(), vec![ev("waiting"), matched("m", "a26_35")]);
        assert_eq!(s.take_events("b").unwrap(), vec![matched("f", "a18_21")]);
    }

    #[test]
    fn leave_and_disconnect_notify_partner_at_once() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        s.take_events("a");
        s.take_events("b");
        s.leave("a", now).unwrap();
        assert_eq!(s.take_events("b").unwrap(), vec![ev("left")]);
        assert_eq!(s.send("b", "эй", now), Err((409, "нет собеседника")));

        let mut s = State::new();
        two(&mut s, now);
        s.take_events("b");
        s.remove("a"); // вкладка закрыта
        assert_eq!(s.take_events("b").unwrap(), vec![ev("left")]);
        assert_eq!(s.online(), 1);
    }

    #[test]
    fn no_immediate_rematch_with_previous_partner() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        s.leave("a", now).unwrap();
        s.find("a", now, any()).unwrap();
        s.find("b", now, any()).unwrap();
        assert!(s.users["a"].waiting && s.users["b"].waiting);
        s.join(ip(3), now, "c".into()).unwrap();
        s.find("c", now, any()).unwrap();
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
            s.find("bad", now, any()).unwrap();
            s.find(name, now, any()).unwrap();
            let banned = s.report(name, now).unwrap();
            assert_eq!(banned, i == 3);
            if i < 3 {
                s.leave(name, now).unwrap();
                s.leave("bad", now).unwrap();
                s.users.get_mut("bad").unwrap().last_partner = None;
            }
        }
        assert_eq!(s.find("bad", now, any()), Err((403, "вы заблокированы")));
        assert_eq!(s.join(ip(9), now, "new".into()), Err((403, "вы заблокированы")));
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
    fn reaper_removes_silent_sessions_and_frees_partner() {
        let (mut s, now) = (State::new(), Instant::now());
        two(&mut s, now);
        s.take_events("b");
        let later = now + IDLE_TIMEOUT + Duration::from_secs(1);
        s.touch("b", later); // b прислал пинг, a молчит
        s.reap(later);
        assert!(s.users.get("a").is_none());
        assert_eq!(s.take_events("b").unwrap(), vec![ev("left")]);
    }

    #[test]
    fn stale_waiting_user_is_not_matched() {
        let (mut s, now) = (State::new(), Instant::now());
        s.join(ip(1), now, "ghost".into()).unwrap();
        s.join(ip(2), now, "live".into()).unwrap();
        s.find("ghost", now, any()).unwrap();
        let later = now + FRESH_FOR_MATCH + Duration::from_secs(1);
        s.touch("live", later);
        s.find("live", later, any()).unwrap();
        assert!(s.users["live"].partner.is_none(), "нельзя соединять с молчащим");
        assert!(s.users["live"].waiting);
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
    fn minors_and_adults_never_match() {
        // подросток ищет «любой», взрослый тоже: всё равно не пара
        assert!(!compatible(&pf("chat", "x", "any", "u17", ""), &pf("chat", "x", "any", "a18_21", "")));
        // у подростка список возрастов всегда сводится к «до 17»
        assert_eq!(pf("chat", "x", "any", "u17", "a18_21,a26_35").ages, vec!["u17"]);
        // взрослый не может выбрать «до 17» в фильтре
        assert_eq!(Prefs::parse("chat", "x", "any", "a22_25", "u17"), Err((400, "выберите возраст собеседника")));
        assert_eq!(pf("chat", "x", "any", "a22_25", "u17,a18_21").ages, vec!["a18_21"]);
        // два подростка соединяются
        assert!(compatible(&pf("chat", "x", "any", "u17", ""), &pf("chat", "m", "any", "u17", "")));
    }

    #[test]
    fn adult_topics_reject_minors() {
        assert_eq!(Prefs::parse("flirt", "x", "any", "u17", ""), Err((400, "выберите свой возраст")));
        assert_eq!(Prefs::parse("rp", "x", "any", "a18_21", ""), Err((400, "выберите свой возраст")));
        assert!(Prefs::parse("flirt", "m", "f", "a18_25", "a18_25,a26_35").is_ok());
        assert_eq!(Prefs::parse("flirt", "m", "f", "a18_25", "u17"), Err((400, "неверный возраст собеседника")));
        assert_eq!(Prefs::parse("sex", "x", "any", "a36", ""), Err((400, "неизвестная тема")));
    }

    #[test]
    fn topics_stay_separate() {
        assert!(!compatible(&pf("flirt", "x", "any", "a26_35", ""), &pf("rp", "x", "any", "a26_35", "")));
        assert!(!compatible(&pf("chat", "x", "any", "a26_35", ""), &pf("rp", "x", "any", "a26_35", "")));
        assert!(compatible(&pf("rp", "x", "any", "a26_35", ""), &pf("rp", "f", "any", "a36", "")));
    }

    #[test]
    fn gender_filter_must_suit_both_sides() {
        let m_seeks_f = pf("chat", "m", "f", "a22_25", "");
        let f_any = pf("chat", "f", "any", "a22_25", "");
        let f_seeks_f = pf("chat", "f", "f", "a22_25", "");
        let m_any = pf("chat", "m", "any", "a22_25", "");
        assert!(compatible(&m_seeks_f, &f_any));
        assert!(!compatible(&m_seeks_f, &f_seeks_f)); // она ищет девушку, а он парень
        assert!(!compatible(&m_seeks_f, &m_any)); // он ищет девушку, а там парень
        assert!(!compatible(&pf("chat", "x", "f", "a22_25", ""), &pf("chat", "x", "any", "a22_25", "")));
    }

    #[test]
    fn age_filter_must_suit_both_sides() {
        let a = pf("chat", "x", "any", "a22_25", "a26_35");
        let b = pf("chat", "x", "any", "a26_35", "a22_25,a36");
        let c = pf("chat", "x", "any", "a36", "");
        assert!(compatible(&a, &b));
        assert!(!compatible(&a, &c)); // a ищет только 26–35
        assert!(!compatible(&b, &pf("chat", "x", "any", "a26_35", "a36"))); // тот ищет 36+, b даёт 26–35
    }

    #[test]
    fn queue_picks_first_compatible_not_just_first() {
        let (mut s, now) = (State::new(), Instant::now());
        for (i, n) in ["w1", "w2", "me"].iter().enumerate() {
            s.join(ip(i as u8 + 1), now, n.to_string()).unwrap();
        }
        s.find("w2", now, pf("chat", "m", "any", "a22_25", "")).unwrap();
        s.find("w1", now, pf("chat", "f", "any", "a36", "a36")).unwrap();
        assert!(s.users["w1"].waiting, "w1 ищет только 36+, w2 ему не подходит");
        s.find("me", now, pf("chat", "m", "any", "a36", "a36")).unwrap();
        assert_eq!(s.users["me"].partner.as_deref(), Some("w1"));
        assert!(s.users["w2"].waiting);
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_str("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
    }
}
