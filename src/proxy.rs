use crate::cfproxy::*;
use crate::config::*;
use crate::crypto::*;
use crate::faketls;
use crate::ws::*;
use crate::{ldebug, linfo, lwarn};
use byteorder::{ByteOrder, LittleEndian};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Fronting flag — proxy/pool.py::_WsPool.try_fronting_first. Апстрим (50c980e)
// стартует с False: иначе каждый коннект сперва ждёт fronting-таймаут.
// ---------------------------------------------------------------------------

static TRY_FRONTING_FIRST: AtomicBool = AtomicBool::new(false);

pub fn ws_pool_fronting_first() -> bool {
    TRY_FRONTING_FIRST.load(Ordering::Relaxed)
}

pub fn set_ws_pool_fronting_first(v: bool) {
    TRY_FRONTING_FIRST.store(v, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

pub fn resolve_configured_target(dc: i32, is_media: bool) -> Option<String> {
    let map = DC_OPT.read();
    if is_media {
        if let Some(t) = map.get(&(-dc)) {
            if !t.is_empty() {
                return Some(t.clone());
            }
        }
    }
    if let Some(t) = map.get(&dc) {
        if !t.is_empty() {
            return Some(t.clone());
        }
    }
    None
}

pub fn resolve_fallback_target(dc: i32, _is_media: bool, is_test: bool) -> String {
    if is_test {
        DC_TEST_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    } else {
        DC_DEFAULT_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    }
}

pub fn ws_domains(dc: i32, is_media: bool) -> Vec<String> {
    let mut effective_dc = dc;
    if let Some(o) = DC_OVERRIDES.get(&dc) {
        effective_dc = *o;
    }
    if is_media {
        vec![
            format!("kws{}-1.web.telegram.org", effective_dc),
            format!("kws{}.web.telegram.org", effective_dc),
        ]
    } else {
        // Как в актуальном Flowseal (utils.ws_domains, 50c980e) и форках
        // crim50n/Alexingin: kwsN-1 — медиа-домен, обычным сессиям он не нужен
        // и лишь удлинял перебор при сбоях.
        vec![format!("kws{}.web.telegram.org", effective_dc)]
    }
}

pub fn ws_path_for(is_test: bool) -> &'static str {
    if is_test {
        WS_PATH_TEST
    } else {
        WS_PATH
    }
}

pub fn media_tag(is_media: bool) -> &'static str {
    if is_media {
        " media"
    } else {
        ""
    }
}

pub fn is_media_int(b: bool) -> i32 {
    if b {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// WsPool — порт proxy/pool.py::_WsPool
// refilling-backoff (1s..3600s), rotation протухших, fronting-first.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DcSlot {
    pub dc: i32,
    pub is_media: i32,
}

pub struct PoolEntry {
    pub ws: RawWebSocket,
    pub created: f64, // monotonic, как time.monotonic() в оригинале
}

struct SlotState {
    queue: Mutex<VecDeque<PoolEntry>>,
    refilling: AtomicI32,
}

pub struct WsPool {
    slots: Mutex<HashMap<DcSlot, Arc<SlotState>>>,
    rotating: Mutex<HashSet<DcSlot>>,
    refill_failures: Mutex<HashMap<DcSlot, (u32, f64)>>,
    cancel_token: CancellationToken,
}

impl WsPool {
    pub fn new(cancel_token: CancellationToken) -> WsPool {
        WsPool {
            slots: Mutex::new(HashMap::new()),
            rotating: Mutex::new(HashSet::new()),
            refill_failures: Mutex::new(HashMap::new()),
            cancel_token,
        }
    }

    async fn get_slot(&self, slot: DcSlot) -> Arc<SlotState> {
        let mut map = self.slots.lock().await;
        map.entry(slot)
            .or_insert_with(|| {
                Arc::new(SlotState {
                    queue: Mutex::new(VecDeque::with_capacity(16)),
                    refilling: AtomicI32::new(0),
                })
            })
            .clone()
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        is_media: bool,
        target_ip: String,
        domains: Vec<String>,
    ) -> Option<RawWebSocket> {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        let state = self.get_slot(slot).await;
        let now = now_monotonic();

        let mut ws: Option<RawWebSocket> = None;
        {
            let mut q = state.queue.lock().await;
            while let Some(entry) = q.pop_front() {
                let age = now - entry.created;
                if age > WS_POOL_REUSE_MAX_AGE
                    || entry.ws.peer_closed()
                {
                    let e = entry;
                    tokio::spawn(async move {
                        e.ws.close().await;
                    });
                    continue;
                }
                STATS.pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "WS pool hit DC{}{} (age={:.1}s, left={})",
                    dc,
                    if is_media { "m" } else { "" },
                    age,
                    q.len()
                );
                ws = Some(entry.ws);
                break;
            }
            if ws.is_none() {
                STATS.pool_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        if ws.is_some() {
            self.report_success(dc, is_media).await;
        }
        self.schedule_refill(slot, target_ip, domains).await;
        ws
    }

    async fn schedule_refill(
        self: &Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
    ) {
        // Нет сети — не пытаемся (и не копим backoff), get() позовёт снова.
        if !net_available() {
            return;
        }
        // Backoff как в оригинале: не раньше _refill_after.
        {
            let failures = self.refill_failures.lock().await;
            if let Some((_, after)) = failures.get(&slot) {
                if now_monotonic() < *after {
                    return;
                }
            }
        }
        let state = self.get_slot(slot).await;
        if state
            .refilling
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        // pool_size <= 0 — преконнект отключён (как pool_size=0 в оригинале).
        if POOL_SIZE.load(Ordering::Relaxed) <= 0 {
            state.refilling.store(0, Ordering::SeqCst);
            return;
        }
        let pool = self.clone();
        spawn_refill_task(pool, slot, state, target_ip, domains);
    }

    async fn refill(
        self: Arc<Self>,
        slot: DcSlot,
        state: Arc<SlotState>,
        target_ip: String,
        domains: Vec<String>,
    ) {
        let epoch = net_epoch();
        let _guard = RefillGuard {
            state: state.clone(),
        };
        let cur_len = state.queue.lock().await.len();
        let pool_sz = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
        if cur_len >= pool_sz || pool_sz == 0 {
            return;
        }
        let needed = pool_sz - cur_len;

        let mut handles = Vec::new();
        for _ in 0..needed {
            let target_ip = target_ip.clone();
            let domains = domains.clone();
            let cancel = self.cancel_token.clone();
            handles.push(tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => None,
                    r = connect_one_ws(&target_ip, &domains) => r,
                }
            }));
        }

        let mut connected = 0;
        for h in handles {
            if let Ok(Some(ws)) = h.await {
                let now = now_monotonic();
                let mut q = state.queue.lock().await;
                if q.len() < 16 {
                    q.push_back(PoolEntry { ws, created: now });
                    connected += 1;
                } else {
                    drop(q);
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                }
            }
        }

        if connected > 0 {
            // IP доказанно доступен: снимаем cooldown, иначе новые коннекты ещё
            // до 2 минут уходили бы в fallback при живом прямом пути.
            if IP_FAIL_UNTIL.write().remove(&target_ip).is_some() {
                linfo!("WS pool reached {}: cooldown cleared", target_ip);
            }
            IP_TIMEOUT_STRIKES.write().remove(&target_ip);
            if failure_counts(epoch) && direct_bad_clear(&target_ip) {
                linfo!("WS pool reached {}: прямой путь снова работает ({})", target_ip, net_kind_name(NET_KIND.load(Ordering::Relaxed)));
            }
            self.report_success(slot.dc, slot.is_media != 0).await;
            self.schedule_rotation(slot, target_ip, domains).await;
        } else if !failure_counts(epoch) {
            // Сеть пропала/сменилась во время пополнения — backoff не наращиваем.
        } else {
            // Экспоненциальный backoff 1s..3600s как в оригинале.
            let mut failures = self.refill_failures.lock().await;
            let count = failures.get(&slot).map(|(c, _)| *c).unwrap_or(0) + 1;
            let shift = (count - 1).min(12);
            let delay = (WS_POOL_REFILL_BACKOFF_INITIAL * (2u64.pow(shift) as f64))
                .min(WS_POOL_REFILL_BACKOFF_MAX);
            failures.insert(slot, (count, now_monotonic() + delay));
            drop(failures);
            linfo!(
                "WS pool refill failed for DC{}{}, retry in {:.0}s",
                slot.dc,
                if slot.is_media != 0 { "m" } else { "" },
                delay
            );
        }
        ldebug!(
            "WS pool refilled DC{}{}: {} ready",
            slot.dc,
            if slot.is_media != 0 { "m" } else { "" },
            state.queue.lock().await.len()
        );
    }

    pub async fn report_success(&self, dc: i32, is_media: bool) {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        self.refill_failures.lock().await.remove(&slot);
    }

    async fn schedule_rotation(
        self: &Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
    ) {
        {
            let mut rotating = self.rotating.lock().await;
            if rotating.contains(&slot) {
                return;
            }
            rotating.insert(slot);
        }
        let pool = self.clone();
        let cancel = self.cancel_token.clone();
        spawn_rotate_task(pool, slot, target_ip, domains, cancel);
    }

    async fn rotate(
        self: Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
        cancel: CancellationToken,
    ) {
        loop {
            // Спим до ближайшего протухания, но не реже CHECK_INTERVAL.
            let sleep_dur = {
                let map = self.slots.lock().await;
                match map.get(&slot) {
                    Some(state) => {
                        let q = state.queue.lock().await;
                        if q.is_empty() {
                            None
                        } else {
                            let now = now_monotonic();
                            let min_expires = q
                                .iter()
                                .map(|e| e.created + WS_POOL_REUSE_MAX_AGE)
                                .fold(f64::INFINITY, f64::min);
                            Some((min_expires - now).clamp(0.0, WS_POOL_CHECK_INTERVAL))
                        }
                    }
                    None => None,
                }
            };
            let sleep_dur = match sleep_dur {
                Some(d) => d,
                None => break,
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs_f64(sleep_dur)) => {}
            }

            let now = now_monotonic();
            let expired_count: usize;
            let ready_count: usize;
            {
                let map = self.slots.lock().await;
                let state = match map.get(&slot) {
                    Some(s) => s.clone(),
                    None => break,
                };
                let mut q = state.queue.lock().await;
                let mut ready = VecDeque::with_capacity(q.len());
                let mut expired = Vec::new();
                while let Some(e) = q.pop_front() {
                    if now - e.created >= WS_POOL_REUSE_MAX_AGE
                        || e.ws.peer_closed()
                    {
                        expired.push(e.ws);
                    } else {
                        ready.push_back(e);
                    }
                }
                expired_count = expired.len();
                *q = ready;
                ready_count = q.len();
                for ws in expired {
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                }
            }
            if expired_count > 0 {
                ldebug!(
                    "WS pool rotated DC{}{}: {} stale, {} ready",
                    slot.dc,
                    if slot.is_media != 0 { "m" } else { "" },
                    expired_count,
                    ready_count
                );
            }
            let pool_sz = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
            if ready_count == 0 {
                break;
            }
            if ready_count < pool_sz {
                self.schedule_refill(slot, target_ip.clone(), domains.clone())
                    .await;
            }
        }
        self.rotating.lock().await.remove(&slot);
    }

    pub async fn warmup(self: &Arc<Self>, dc_opt_map: &HashMap<i32, String>) {
        let mut ndcs = 0;
        for (dc, target_ip) in dc_opt_map {
            if target_ip.is_empty() {
                continue;
            }
            ndcs += 1;
            for is_media in [false, true] {
                let domains = ws_domains(*dc, is_media);
                let slot = DcSlot {
                    dc: *dc,
                    is_media: is_media_int(is_media),
                };
                self.schedule_refill(slot, target_ip.clone(), domains).await;
            }
        }
        linfo!("WS pool warmup started for {} DC(s)", ndcs);
    }

    pub async fn idle_count(&self) -> usize {
        let map = self.slots.lock().await;
        let mut count = 0;
        for s in map.values() {
            count += s.queue.lock().await.len();
        }
        count
    }

    pub async fn close_all(&self) {
        let map = self.slots.lock().await;
        for s in map.values() {
            let mut q = s.queue.lock().await;
            for e in q.drain(..) {
                tokio::spawn(async move {
                    e.ws.close().await;
                });
            }
        }
    }

    pub async fn reset(&self) {
        self.close_all().await;
        self.slots.lock().await.clear();
        self.rotating.lock().await.clear();
        self.refill_failures.lock().await.clear();
        set_ws_pool_fronting_first(false);
    }
}

// RefillGuard снимает флаг refilling при выходе (аналог finally: discard).
struct RefillGuard {
    state: Arc<SlotState>,
}
impl Drop for RefillGuard {
    fn drop(&mut self) {
        self.state.refilling.store(0, Ordering::SeqCst);
    }
}

// Синхронные спавн-хелперы: разрывают цикл типов async-future
// (schedule_refill → refill → schedule_rotation → rotate → schedule_refill),
// о который спотыкается rustc (E0391). Sync-fn не вкладывает future одной
// async-функции в другую — внутри только JoinHandle.
fn spawn_refill_task(
    pool: Arc<WsPool>,
    slot: DcSlot,
    state: Arc<SlotState>,
    target_ip: String,
    domains: Vec<String>,
) {
    tokio::spawn(async move {
        pool.refill(slot, state, target_ip, domains).await;
    });
}

fn spawn_rotate_task(
    pool: Arc<WsPool>,
    slot: DcSlot,
    target_ip: String,
    domains: Vec<String>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        pool.rotate(slot, target_ip, domains, cancel).await;
    });
}

// ---------------------------------------------------------------------------
// CfWorkerPool — порт proxy/pool.py::_CfWorkerPool
// ---------------------------------------------------------------------------

pub struct CfWorkerEntry {
    pub ws: RawWebSocket,
    pub created: f64,
    pub worker_domain: String,
}

pub struct CfWorkerPool {
    idle: Mutex<HashMap<i32, VecDeque<CfWorkerEntry>>>,
    refilling: Mutex<HashSet<i32>>,
    exhausted_until: Mutex<HashMap<String, f64>>,
    cancel_token: CancellationToken,
}

impl CfWorkerPool {
    pub fn new(cancel_token: CancellationToken) -> CfWorkerPool {
        CfWorkerPool {
            idle: Mutex::new(HashMap::new()),
            refilling: Mutex::new(HashSet::new()),
            exhausted_until: Mutex::new(HashMap::new()),
            cancel_token,
        }
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: String,
        worker_domains: Vec<String>,
    ) -> Option<(RawWebSocket, String)> {
        let now = now_monotonic();
        let entry = {
            let mut map = self.idle.lock().await;
            let bucket = map.entry(dc).or_insert_with(VecDeque::new);
            let mut hit = None;
            while let Some(e) = bucket.pop_front() {
                if now - e.created > CF_WORKER_POOL_MAX_AGE || e.ws.peer_closed() {
                    let ws = e.ws;
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                    continue;
                }
                hit = Some(e);
                break;
            }
            hit
        };
        match entry {
            Some(e) => {
                STATS.cf_pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "CF worker pool hit DC{} via {} (age={:.1}s)",
                    dc,
                    e.worker_domain,
                    now - e.created
                );
                self.schedule_refill(dc, fallback_dst, worker_domains).await;
                Some((e.ws, e.worker_domain))
            }
            None => {
                STATS.cf_pool_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    async fn schedule_refill(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: String,
        worker_domains: Vec<String>,
    ) {
        // Раньше флаг refilling ставился, а refill не запускался и флаг никто
        // не снимал — после первого попадания пул для DC больше не пополнялся.
        // refill_now сам ставит/снимает флаг и уважает PER_DC_LIMIT.
        self.refill_now(dc, fallback_dst, worker_domains).await;
    }

    pub async fn refill_now(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: String,
        worker_domains: Vec<String>,
    ) {
        let should = {
            let mut r = self.refilling.lock().await;
            if r.contains(&dc) {
                false
            } else {
                r.insert(dc);
                true
            }
        };
        if !should {
            return;
        }
        let pool = self.clone();
        let cancel = self.cancel_token.clone();
        tokio::spawn(async move {
            let _cancel = cancel;
            {
                let map = pool.idle.lock().await;
                let cur = map.get(&dc).map(|b| b.len()).unwrap_or(0);
                if cur >= CF_WORKER_PER_DC_LIMIT.min(POOL_SIZE.load(Ordering::Relaxed).max(0) as usize) {
                    pool.refilling.lock().await.remove(&dc);
                    return;
                }
            }
            if let Some((ws, domain)) = pool
                .connect_one(worker_domains.clone(), fallback_dst.clone(), dc)
                .await
            {
                let mut map = pool.idle.lock().await;
                map.entry(dc)
                    .or_insert_with(VecDeque::new)
                    .push_back(CfWorkerEntry {
                        ws,
                        created: now_monotonic(),
                        worker_domain: domain,
                    });
                ldebug!("CF worker pool refilled DC{}: ready", dc);
            }
            pool.refilling.lock().await.remove(&dc);
        });
    }

    async fn connect_one(
        &self,
        worker_domains: Vec<String>,
        fallback_dst: String,
        dc: i32,
    ) -> Option<(RawWebSocket, String)> {
        let secure = !DISABLE_SECURE.load(Ordering::Relaxed);
        let query = format!("dst={}&dc={}", fallback_dst, dc);
        let path = format!("/apiws?{}", query);
        for worker_domain in self.available_domains(worker_domains).await {
            match ws_connect_full_opts(&worker_domain, &worker_domain, &path, 8.0, None, Some(secure))
                .await
            {
                Ok(ws) => return Some((ws, worker_domain)),
                Err(exc) => {
                    self.report_failure(&worker_domain, &exc).await;
                }
            }
        }
        None
    }

    pub async fn available_domains(&self, worker_domains: Vec<String>) -> Vec<String> {
        let now = now_unix_f64();
        let mut exhausted = self.exhausted_until.lock().await;
        let mut domains = Vec::new();
        let mut seen = HashSet::new();
        for domain in worker_domains {
            if !seen.insert(domain.clone()) {
                continue;
            }
            if let Some(until) = exhausted.get(&domain) {
                if *until > now {
                    continue;
                }
            }
            exhausted.remove(&domain);
            domains.push(domain);
        }
        drop(exhausted);
        // random.shuffle как в оригинале.
        {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            domains.shuffle(&mut rng);
        }
        domains
    }

    pub async fn report_failure(&self, _worker_domain: &str, _exc: &WsError) {
        // TODO: picks up 429/daily-limit handling — как в оригинале пока no-op.
        return;
    }

    pub async fn warmup(self: &Arc<Self>, dc_opt_map: &HashMap<i32, String>) {
        let worker_domains = CF_WORKER_DOMAINS.read().clone();
        if worker_domains.is_empty() {
            return;
        }
        // CF worker греем только для DC, которых НЕТ в прямых редиректах.
        let fallbacks: Vec<(i32, String)> = DC_DEFAULT_IPS
            .iter()
            .filter(|(dc, _)| !dc_opt_map.contains_key(dc))
            .map(|(dc, ip)| (*dc, ip.to_string()))
            .collect();
        if fallbacks.is_empty() {
            return;
        }
        for (dc, fallback_dst) in &fallbacks {
            self.refill_now(*dc, fallback_dst.clone(), worker_domains.clone())
                .await;
        }
        linfo!("CF worker pool warmup started for {} DC(s)", fallbacks.len());
    }

    pub async fn close_all(&self) {
        let mut map = self.idle.lock().await;
        for bucket in map.values_mut() {
            for e in bucket.drain(..) {
                tokio::spawn(async move {
                    e.ws.close().await;
                });
            }
        }
    }

    pub async fn reset(&self) {
        self.close_all().await;
        self.idle.lock().await.clear();
        self.refilling.lock().await.clear();
        self.exhausted_until.lock().await.clear();
    }
}

// ---------------------------------------------------------------------------
// Shared pools (WS + CF worker) — один Arc на соединение.
// ---------------------------------------------------------------------------

pub struct ProxyPools {
    pub ws: Arc<WsPool>,
    pub cf_worker: Arc<CfWorkerPool>,
}

impl ProxyPools {
    pub fn new(cancel_token: CancellationToken) -> Self {
        ProxyPools {
            ws: Arc::new(WsPool::new(cancel_token.clone())),
            cf_worker: Arc::new(CfWorkerPool::new(cancel_token)),
        }
    }

    pub async fn warmup(&self, dc_opt_map: &HashMap<i32, String>) {
        self.ws.warmup(dc_opt_map).await;
        self.cf_worker.warmup(dc_opt_map).await;
    }

    pub async fn close_all(&self) {
        self.ws.close_all().await;
        self.cf_worker.close_all().await;
    }

    pub async fn reset(&self) {
        self.ws.reset().await;
        self.cf_worker.reset().await;
    }
}

// ---------------------------------------------------------------------------
// HTTP transport detection
// ---------------------------------------------------------------------------

pub fn is_http_transport(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    &data[..4] == b"POST"
        || &data[..3] == b"GET"
        || &data[..4] == b"HEAD"
        || (data.len() >= 7 && &data[..7] == b"OPTIONS")
}

// ---------------------------------------------------------------------------
// Bridge WS — generic core + TcpStream wrapper.
// Сессионная статистика как в bridge_ws_reencrypt оригинала.
// ---------------------------------------------------------------------------

/// Окно «запрос без ответа» для детектора зависания медиа.
#[derive(Default)]
struct StallWindow {
    pending_since: Option<std::time::Instant>,
    up: i64,
    down: i64,
    last_down: Option<std::time::Instant>,
}

impl StallWindow {
    fn reset(&mut self) {
        self.pending_since = None;
        self.up = 0;
        self.down = 0;
    }

    fn on_request(&mut self, n: i64) {
        let now = std::time::Instant::now();
        // TG уже получил что-то после открытия окна — это новый запрос.
        let answered = match (self.pending_since, self.last_down) {
            (Some(since), Some(last)) => last >= since,
            _ => false,
        };
        if self.pending_since.is_none() || answered {
            self.pending_since = Some(now);
            self.up = 0;
            self.down = 0;
        }
        self.up += n;
    }

    /// true — пришёл осмысленный ответ, прямой WS отвечает.
    fn on_response(&mut self, n: i64) -> bool {
        self.last_down = Some(std::time::Instant::now());
        if self.pending_since.is_some() {
            self.down += n;
            if self.down >= STALL_MIN_MEANINGFUL_DOWN {
                self.reset();
                return true;
            }
        }
        false
    }

    fn is_stalled(&self) -> Option<(i64, i64)> {
        let since = self.pending_since?;
        if since.elapsed() < STALL_TIMEOUT
            || self.up < STALL_MIN_PENDING_UP
            || self.down >= STALL_MIN_MEANINGFUL_DOWN
        {
            return None;
        }
        // Вниз должно молчать столько же: медленный, но идущий поток — не зависание.
        if let Some(last) = self.last_down {
            if last.elapsed() < STALL_TIMEOUT {
                return None;
            }
        }
        Some((self.up, self.down))
    }
}

pub async fn bridge_ws<R, W>(
    conn_read: R,
    conn_write: W,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    mut splitter: Option<MsgSplitter>,
    mut clt_dec: TrackedStream,
    mut clt_enc: TrackedStream,
    mut tg_enc: TrackedStream,
    mut tg_dec: TrackedStream,
    cancel_token: CancellationToken,
    stall_key: Option<DcKey>,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let dc_tag = format!("DC{}{}", dc, if is_media { "m" } else { "" });
    let ws = Arc::new(ws);
    // Sticky: Notify::notify_waiters терял сигнал, если вторая половина
    // в этот момент висела в write/send — полумёртвый мост жил до таймаута.
    let cancel = cancel_token.child_token();
    let start = now_monotonic();

    let mut conn_read = conn_read;
    let mut conn_write = conn_write;

    let last_activity = Arc::new(Mutex::new(std::time::Instant::now()));

    // Детектор зависания медиа (только медиа по прямому WS, stall_key = Some).
    // Окно «запрос без ответа»: открывается на данных от TG, закрывается, когда
    // пришло >= STALL_MIN_MEANINGFUL_DOWN. Если TG что-то получил после открытия
    // окна, новый запрос открывает окно заново (иначе мелкий ответ + долгая
    // пауза давали бы ложное зависание). Зависание: окно старше STALL_TIMEOUT,
    // запросов >= STALL_MIN_PENDING_UP, ответа < порога и вниз тишина.
    // Instant и таймеры tokio идут только пока CPU не спит — сон не даёт
    // ложных срабатываний.
    let stall = stall_key.map(|_| Arc::new(parking_lot::Mutex::new(StallWindow::default())));
    let close_reason_stall = Arc::new(Mutex::new(String::new()));
    let stall_task = match (stall_key, stall.clone()) {
        (Some(key), Some(stall_w)) => {
            let cancel_st = cancel.clone();
            let cancel_token_st = cancel_token.clone();
            let reason = close_reason_stall.clone();
            let label_st = label.clone();
            let epoch_start = net_epoch();
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = cancel_token_st.cancelled() => return,
                        _ = cancel_st.cancelled() => return,
                        _ = interval.tick() => {}
                    }
                    if !failure_counts(epoch_start) {
                        // Сети нет или она сменилась — это не «душат медиа».
                        stall_w.lock().reset();
                        continue;
                    }
                    let stalled = {
                        let w = stall_w.lock();
                        w.is_stalled()
                    };
                    let Some((up, down)) = stalled else { continue };
                    let (strikes, block) = breaker_record_stall(key);
                    let msg = format!(
                        "медиа зависло: ^{}B без ответа (v{}B) {}s; прямой WS в обход на {:.0}s ({}, зависание #{})",
                        up, down, STALL_TIMEOUT.as_secs(), block,
                        net_kind_name(NET_KIND.load(Ordering::Relaxed)), strikes
                    );
                    lwarn!("[{}] {}", label_st, msg);
                    *reason.lock().await = "upstream: media stall".to_string();
                    cancel_st.cancel();
                    return;
                }
            }))
        }
        _ => None,
    };

    // Keepalive ровно как в 1.3.1: ping только после BRIDGE_PING_INTERVAL
    // тишины в обе стороны, ответ не проверяем. В 1.3.2 пинги каждые 45s и
    // разрыв по отсутствию pong ухудшили мобильный интернет; у Flowseal частые
    // пинги (30s) тоже рвали сессии и были откачены (#925 -> #1036).
    let ws_ping = ws.clone();
    let la_ping = last_activity.clone();
    let cancel_ping = cancel.clone();
    let cancel_token_ping = cancel_token.clone();
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(BRIDGE_PING_INTERVAL / 2);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel_token_ping.cancelled() => return,
                _ = cancel_ping.cancelled() => return,
                _ = interval.tick() => {
                    let idle = la_ping.lock().await.elapsed();
                    if idle > BRIDGE_PING_INTERVAL {
                        if ws_ping.send_ping().await.is_err() {
                            cancel_ping.cancel();
                            return;
                        }
                    }
                }
            }
        }
    });

    // up: client -> ws
    let ws_up = ws.clone();
    let la_up = last_activity.clone();
    let stall_up = stall.clone();
    let cancel_up = cancel.clone();
    let cancel_token_up = cancel_token.clone();
    let up_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let up_packets = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let up_bytes_c = up_bytes.clone();
    let up_packets_c = up_packets.clone();
    let close_reason_up = Arc::new(Mutex::new(String::new()));
    let close_reason_up_c = close_reason_up.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; WS_BRIDGE_CHUNK_SIZE];
        loop {
            let read_res = tokio::select! {
                _ = cancel_token_up.cancelled() => break,
                _ = cancel_up.cancelled() => break,
                r = tokio::time::timeout(BRIDGE_CLIENT_IDLE_TIMEOUT, conn_read.read(&mut buf)) => r,
            };
            let n = match read_res {
                Ok(Ok(0)) => {
                    // EOF: flush splitter tail
                    if let Some(sp) = splitter.as_mut() {
                        let tail = sp.flush();
                        if !tail.is_empty() {
                            let r = if tail.len() > 1 {
                                ws_up.send_batch(&tail).await
                            } else {
                                ws_up.send(&tail[0]).await
                            };
                            if r.is_err() {
                                *close_reason_up_c.lock().await =
                                    "upstream: send_failed".to_string();
                                break;
                            }
                        }
                    }
                    break;
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    *close_reason_up_c.lock().await =
                        format!("client: {}", e.kind());
                    break;
                }
                Err(_) => {
                    *close_reason_up_c.lock().await = "client: timeout".to_string();
                    break;
                }
            };

            let chunk = &mut buf[..n];
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            up_bytes_c.fetch_add(n as i64, Ordering::Relaxed);
            up_packets_c.fetch_add(1, Ordering::Relaxed);
            *la_up.lock().await = std::time::Instant::now();
            if let Some(w) = &stall_up {
                w.lock().on_request(n as i64);
            }

            clt_dec.xor(chunk);
            tg_enc.xor(chunk);

            let send_err = {
                if let Some(sp) = splitter.as_mut() {
                    let parts = sp.split(chunk);
                    if parts.len() > 1 {
                        ws_up.send_batch(&parts).await.is_err()
                    } else if parts.len() == 1 {
                        ws_up.send(&parts[0]).await.is_err()
                    } else {
                        false
                    }
                } else {
                    ws_up.send(chunk).await.is_err()
                }
            };
            if send_err {
                *close_reason_up_c.lock().await = "upstream: send_failed".to_string();
                break;
            }
        }
        cancel_up.cancel();
    });

    // down: ws -> client
    let ws_down = ws.clone();
    let la_down = last_activity.clone();
    let stall_down = stall.clone();
    let cancel_down = cancel.clone();
    let cancel_token_down = cancel_token.clone();
    let down_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let down_packets = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let down_bytes_c = down_bytes.clone();
    let down_packets_c = down_packets.clone();
    let close_reason_down = Arc::new(Mutex::new(String::new()));
    let close_reason_down_c = close_reason_down.clone();
    let down_task = tokio::spawn(async move {
        loop {
            let recv_res = tokio::select! {
                _ = cancel_token_down.cancelled() => break,
                _ = cancel_down.cancelled() => break,
                r = ws_down.recv_with_timeout(BRIDGE_READ_TIMEOUT) => r,
            };
            let mut data = match recv_res {
                Ok(d) => d,
                Err(WsError::Timeout) => {
                    *close_reason_down_c.lock().await =
                        "upstream: timeout".to_string();
                    break;
                }
                Err(_) => {
                    let cur = close_reason_down_c.lock().await.clone();
                    if cur.is_empty() {
                        *close_reason_down_c.lock().await =
                            "upstream: ws_close".to_string();
                    }
                    break;
                }
            };
            let n = data.len();
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            down_bytes_c.fetch_add(n as i64, Ordering::Relaxed);
            down_packets_c.fetch_add(1, Ordering::Relaxed);
            *la_down.lock().await = std::time::Instant::now();
            if let Some(w) = &stall_down {
                let responsive = w.lock().on_response(n as i64);
                if responsive {
                    if let Some(k) = stall_key {
                        breaker_record_responsive(k);
                    }
                }
            }

            tg_dec.xor(&mut data);
            clt_enc.xor(&mut data);
            let wr = conn_write.write_all(&data).await;
            if wr.is_err() {
                *close_reason_down_c.lock().await = "client: write_failed".to_string();
                break;
            }
        }
        cancel_down.cancel();
    });

    let _ = up_task.await;
    let _ = down_task.await;
    cancel.cancel();
    ping_task.abort();
    if let Some(t) = stall_task {
        t.abort();
    }

    let close_reason = {
        let up_r = close_reason_up.lock().await.clone();
        let down_r = close_reason_down.lock().await.clone();
        let stall_r = close_reason_stall.lock().await.clone();
        if !stall_r.is_empty() {
            stall_r
        } else if !down_r.is_empty() {
            down_r
        } else if !up_r.is_empty() {
            up_r
        } else {
            "normal".to_string()
        }
    };
    let elapsed = now_monotonic() - start;
    linfo!(
        "[{}] {} WS session closed ({}): ^{}{} ({} pkts) v{}{} ({} pkts) in {:.1}s",
        label,
        dc_tag,
        close_reason,
        human_bytes(up_bytes.load(Ordering::Relaxed)),
        "",
        up_packets.load(Ordering::Relaxed),
        human_bytes(down_bytes.load(Ordering::Relaxed)),
        "",
        down_packets.load(Ordering::Relaxed),
        elapsed
    );

    ws.close().await;
}

/// Совместимость: bridge по TcpStream (разрезаем внутри).
pub async fn bridge_ws_stream(
    conn: TcpStream,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (conn_read, conn_write) = tokio::io::split(conn);
    bridge_ws(
        conn_read,
        conn_write,
        ws,
        label,
        dc,
        is_media,
        splitter,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
        None,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Bridge TCP — generic core + wrapper.
// ---------------------------------------------------------------------------

pub async fn bridge_tcp<CR, CW>(
    mut c_read: CR,
    mut c_write: CW,
    mut remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) where
    CR: AsyncReadExt + Unpin + Send + 'static,
    CW: AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut r_read, mut r_write) = remote.split();

    let clt_dec = Arc::new(Mutex::new(clt_dec));
    let clt_enc = Arc::new(Mutex::new(clt_enc));
    let tg_enc = Arc::new(Mutex::new(tg_enc));
    let tg_dec = Arc::new(Mutex::new(tg_dec));

    let cancel = cancel_token.child_token();

    let cancel_up = cancel.clone();
    let cancel_token_up = cancel_token.clone();
    let clt_dec_up = clt_dec.clone();
    let tg_enc_up = tg_enc.clone();
    let up = async move {
        let mut buf = vec![0u8; 131072];
        loop {
            let n = tokio::select! {
                _ = cancel_token_up.cancelled() => break,
                _ = cancel_up.cancelled() => break,
                r = tokio::time::timeout(BRIDGE_CLIENT_IDLE_TIMEOUT, c_read.read(&mut buf)) => match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                },
            };
            let chunk = &mut buf[..n];
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            clt_dec_up.lock().await.xor(chunk);
            tg_enc_up.lock().await.xor(chunk);
            if r_write.write_all(chunk).await.is_err() {
                break;
            }
        }
        cancel_up.cancel();
    };

    let cancel_down = cancel.clone();
    let cancel_token_down = cancel_token.clone();
    let tg_dec_down = tg_dec.clone();
    let clt_enc_down = clt_enc.clone();
    let down = async move {
        let mut buf = vec![0u8; 131072];
        loop {
            let n = tokio::select! {
                _ = cancel_token_down.cancelled() => break,
                _ = cancel_down.cancelled() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, r_read.read(&mut buf)) => match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                },
            };
            let chunk = &mut buf[..n];
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            tg_dec_down.lock().await.xor(chunk);
            clt_enc_down.lock().await.xor(chunk);
            if c_write.write_all(chunk).await.is_err() {
                break;
            }
        }
        cancel_down.cancel();
    };

    tokio::join!(up, down);
    let _ = (clt_dec, clt_enc, tg_enc, tg_dec);
}

pub async fn bridge_tcp_stream(
    client: TcpStream,
    remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (c_read, c_write) = tokio::io::split(client);
    bridge_tcp(
        c_read,
        c_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// TCP fallback — порт bridge._tcp_fallback
// ---------------------------------------------------------------------------

// Backoff как в bridge._tcp_fallback апстрима: заблокированный по IP DC не
// должен съедать TCP_CONNECT_TIMEOUT на каждом новом коннекте перед CF.
static TCP_BACKOFF: once_cell::sync::Lazy<parking_lot::Mutex<HashMap<String, (u32, f64)>>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(HashMap::new()));

pub fn reset_tcp_backoff() {
    TCP_BACKOFF.lock().clear();
}

// ---------------------------------------------------------------------------
// Самовосстановление (идея форка Alexingin): если несколько подключений подряд
// не нашли ни одного рабочего маршрута, снимаем все накопленные блокировки и
// сбрасываем пул — как при смене сети. Раньше в такой ситуации помогал только
// ручной перезапуск прокси. Срабатывает не чаще раза в минуту.
// ---------------------------------------------------------------------------

static FAIL_STREAK: AtomicI32 = AtomicI32::new(0);
static LAST_AUTO_RESET: parking_lot::Mutex<f64> = parking_lot::Mutex::new(f64::NEG_INFINITY);
const AUTO_RESET_FAIL_STREAK: i32 = 4;
const AUTO_RESET_MIN_INTERVAL: f64 = 60.0;

fn note_connection_success() {
    FAIL_STREAK.store(0, Ordering::Relaxed);
}

async fn note_connection_failure(pools: &ProxyPools) {
    if !net_available() {
        return;
    }
    let streak = FAIL_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
    if streak < AUTO_RESET_FAIL_STREAK {
        return;
    }
    {
        let now = now_monotonic();
        let mut last = LAST_AUTO_RESET.lock();
        if now - *last < AUTO_RESET_MIN_INTERVAL {
            return;
        }
        *last = now;
    }
    FAIL_STREAK.store(0, Ordering::Relaxed);
    lwarn!("{} подключений подряд без маршрута -> сброс блокировок и пула", streak);
    reset_route_state();
    breaker_clear_all();
    pools.reset().await;
}

/// Снять все cooldown'ы/блокировки маршрутов (смена сети, самовосстановление).
pub fn reset_route_state() {
    clear_failure_state();
    reset_tcp_backoff();
    clear_cfproxy_429_cooldowns();
    clear_doh_cache();
}

fn tcp_backoff_active(key: &str) -> bool {
    TCP_BACKOFF
        .lock()
        .get(key)
        .map(|(_, until)| now_monotonic() < *until)
        .unwrap_or(false)
}

fn tcp_backoff_fail(key: &str) -> f64 {
    let mut map = TCP_BACKOFF.lock();
    let failures = map.get(key).map(|(c, _)| *c).unwrap_or(0) + 1;
    let delay = (TCP_BACKOFF_INITIAL * 2f64.powi((failures - 1).min(7) as i32)).min(TCP_BACKOFF_MAX);
    map.insert(key.to_string(), (failures, now_monotonic() + delay));
    delay
}

// Только устанавливает TCP и шлёт init, НЕ трогая conn — при провале те же
// halves уходят дальше в CF.
async fn tcp_connect_fallback(dst: &str, port: u16, init: &[u8], label: &str) -> Option<TcpStream> {
    let addr = format!("{}:{}", dst, port);
    let epoch = net_epoch();
    if tcp_backoff_active(&addr) {
        ldebug!("[{}] TCP fallback to {} skipped (backoff)", label, addr);
        return None;
    }
    // Single-flight (как у Alexingin / Flowseal 50c980e): пока к адресу уже идёт
    // попытка, остальные не ждут свои 4s таймаута, а сразу идут дальше (в CF).
    // На LTE было 16 одновременных попыток к одному заблокированному адресу.
    // Адрес, к которому TCP уже проходил, не ограничиваем: там параллельные
    // подключения — норма (например, DC1/3/5 на Wi-Fi).
    static TCP_CONNECTING: once_cell::sync::Lazy<parking_lot::Mutex<HashSet<String>>> =
        once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(HashSet::new()));
    static TCP_KNOWN_OK: once_cell::sync::Lazy<parking_lot::Mutex<HashSet<String>>> =
        once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(HashSet::new()));
    let known_ok = TCP_KNOWN_OK.lock().contains(&addr);
    if !TCP_CONNECTING.lock().insert(addr.clone()) && !known_ok {
        ldebug!("[{}] TCP fallback to {} skipped (already connecting)", label, addr);
        return None;
    }
    struct ConnectingGuard(String);
    impl Drop for ConnectingGuard {
        fn drop(&mut self) {
            TCP_CONNECTING.lock().remove(&self.0);
        }
    }
    let _connecting = ConnectingGuard(addr.clone());
    let res = tokio::time::timeout(TCP_CONNECT_TIMEOUT, async {
        let mut remote = TcpStream::connect(&addr).await?;
        let _ = remote.set_nodelay(true);
        remote.write_all(init).await?;
        Ok::<_, std::io::Error>(remote)
    })
    .await;
    match res {
        Ok(Ok(remote)) => {
            TCP_BACKOFF.lock().remove(&addr);
            TCP_KNOWN_OK.lock().insert(addr.clone());
            Some(remote)
        }
        Ok(Err(e)) => {
            TCP_KNOWN_OK.lock().remove(&addr);
            if !failure_counts(epoch) {
                return None;
            }
            let delay = tcp_backoff_fail(&addr);
            lwarn!("[{}] TCP fallback to {} failed: {}; retry in {:.0}s", label, addr, e, delay);
            None
        }
        Err(_) => {
            TCP_KNOWN_OK.lock().remove(&addr);
            if !failure_counts(epoch) {
                return None;
            }
            let delay = tcp_backoff_fail(&addr);
            lwarn!("[{}] TCP fallback to {} failed: timeout; retry in {:.0}s", label, addr, delay);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Cfproxy fallback — мобильная версия (параллель + 429 cooldown + DoH),
// путь и secure как в оригинале.
// ---------------------------------------------------------------------------

async fn try_cfproxy_base_domain(
    dc: i32,
    base_domain: &str,
    ws_path: &str,
) -> (Option<RawWebSocket>, String) {
    let base_domain = normalize_cf_domain(base_domain);
    if base_domain.is_empty() {
        return (None, String::new());
    }
    let remaining = cfproxy_429_cooldown_remaining(&base_domain);
    if remaining > Duration::ZERO {
        ldebug!(
            " CF skip {}: 429 cooldown {:.0}s",
            base_domain,
            remaining.as_secs_f64().ceil()
        );
        return (None, String::new());
    }
    let _permit = match acquire_cfproxy_attempt_slot().await {
        Some(p) => p,
        None => return (None, String::new()),
    };

    let domain = format!("kws{}.{}", dc, base_domain);
    ldebug!(" CF try {}", domain);

    let (ws, resolved_ip, err) = cf_connect_domain(&domain, ws_path, 5.0).await;
    if let Some(e) = err {
        // Cooldown ставим ТОЛЬКО при HTTP 429, иначе любой reset/timeout
        // выжигал бы домены и плодил лавину cooldown.
        if is_http_status_error(&e, 429) {
            mark_cfproxy_429_cooldown(&base_domain, &e);
        }
        if !resolved_ip.is_empty() {
            log_cf_conn_error(
                &format!(" CF fail {} via {}: {}", domain, resolved_ip, e.compact()),
                &e,
            );
        } else {
            log_cf_conn_error(&format!(" CF fail {}: {}", domain, e.compact()), &e);
        }
        return (None, String::new());
    }

    clear_cfproxy_429_cooldown(&base_domain);
    if !resolved_ip.is_empty() {
        ldebug!(" CF ok {} via {}", domain, resolved_ip);
    } else {
        ldebug!(" CF ok {} via hostname", domain);
    }
    (ws, base_domain)
}

// Только устанавливает WS-соединение через CF, НЕ трогая conn.
async fn cfproxy_acquire_ws(
    dc: i32,
    is_media: bool,
    ws_path: &str,
    cancel_token: &CancellationToken,
) -> Option<(RawWebSocket, String)> {
    let (enabled, domains) = {
        let cfg = CFPROXY.read();
        (
            CFPROXY_ENABLED.load(Ordering::Relaxed),
            cfg.domains.clone(),
        )
    };
    if !enabled || domains.is_empty() {
        return None;
    }

    let ordered = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
    if ordered.is_empty() {
        return None;
    }

    let m_tag = if is_media { " media" } else { "" };
    ldebug!(" CF fallback DC{}{}: {} домен(ов)", dc, m_tag, ordered.len());

    let mut ws: Option<RawWebSocket> = None;
    let mut chosen_domain = String::new();

    if !ordered.is_empty() && !ordered[0].is_empty() {
        let (w, d) = try_cfproxy_base_domain(dc, &ordered[0], ws_path).await;
        ws = w;
        chosen_domain = d;
    }

    if ws.is_none() && ordered.len() > 1 {
        // Берём первый успешный домен. Раньше ждали завершения ВСЕХ попыток
        // (до ~20 доменов по 2 параллельно, каждая до ~10s) — TG висел больше
        // минуты, хотя рабочий домен нашёлся за пару секунд. Общий дедлайн не
        // даёт попыткам от давно ушедших клиентов копиться (при белых списках)
        // и занимать глобальный семафор CF у новых соединений.
        let sem = Arc::new(tokio::sync::Semaphore::new(CFPROXY_FALLBACK_PARALLEL));
        let mut set = tokio::task::JoinSet::new();
        for bd in ordered[1..].to_vec() {
            let sem = sem.clone();
            let ws_path = ws_path.to_string();
            set.spawn(async move {
                let _p = sem.acquire_owned().await.ok()?;
                let (w, d) = try_cfproxy_base_domain(dc, &bd, &ws_path).await;
                w.map(|ws| (ws, d))
            });
        }
        let deadline = tokio::time::sleep(CFPROXY_ACQUIRE_DEADLINE);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                _ = &mut deadline => {
                    lwarn!(" CF fallback DC{}{}: дедлайн {}s", dc, m_tag, CFPROXY_ACQUIRE_DEADLINE.as_secs());
                    break;
                }
                r = set.join_next() => match r {
                    None => break,
                    Some(Ok(Some((w, d)))) => {
                        ws = Some(w);
                        chosen_domain = d;
                        break;
                    }
                    Some(_) => continue,
                },
            }
        }
        // Остальные попытки больше не нужны.
        set.abort_all();
    }

    match ws {
        Some(w) => {
            if !chosen_domain.is_empty() {
                if crate::balancer::BALANCER.write().update_domain_for_dc(dc, &chosen_domain) {
                    linfo!(" CF домен для DC{} -> {}", dc, chosen_domain);
                }
            }
            Some((w, chosen_domain))
        }
        None => {
            lwarn!(" CF fallback DC{}{}: все CF домены недоступны", dc, m_tag);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// doFallback — порт bridge.do_fallback: cf_worker -> cf -> tcp.
// CF не "съедает" conn при провале: тот же conn уходит в TCP fallback.
// halves передаются дальше только в успешную ветвь: worker-ws и cf-ws
// добываются БЕЗ halves, затем halves уходят в bridge/tcp.
// ---------------------------------------------------------------------------

pub async fn do_fallback<R, W>(
    pools: &ProxyPools,
    conn_read: R,
    conn_write: W,
    relay_init: &[u8],
    label: String,
    dc: i32,
    is_test: bool,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: &TrackedStream,
    clt_enc: &TrackedStream,
    tg_enc: &TrackedStream,
    tg_dec: &TrackedStream,
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let m_tag = if is_media { " media" } else { "" };
    let fallback_dst = resolve_fallback_target(dc, is_media, is_test);
    let use_cf = CFPROXY_ENABLED.load(Ordering::Relaxed) && !is_test;
    let worker_domains = CF_WORKER_DOMAINS.read().clone();
    let ws_path = ws_path_for(is_test);
    let secure_port = if DISABLE_SECURE.load(Ordering::Relaxed) { 80 } else { 443 };
    let use_worker = !worker_domains.is_empty() && !fallback_dst.is_empty() && !is_test;

    // Шаг 1: tcp. В РФ CF режется ТСПУ (обрыв после ~16KB), поэтому в отличие
    // от апстрима (worker -> cf -> tcp) прямой TCP пробуем раньше CF.
    if !fallback_dst.is_empty() {
        linfo!(
            "[{}] DC{}{} -> TCP fallback to {}:{}",
            label, dc, m_tag, fallback_dst, secure_port
        );
        if let Some(remote) =
            tcp_connect_fallback(&fallback_dst, secure_port, relay_init, &label).await
        {
            STATS.connections_tcp_fallback.fetch_add(1, Ordering::Relaxed);
            note_connection_success();
            bridge_tcp(
                conn_read,
                conn_write,
                remote,
                clt_dec.clone_state(),
                clt_enc.clone_state(),
                tg_enc.clone_state(),
                tg_dec.clone_state(),
                cancel_token,
            )
            .await;
            return true;
        }
    }

    // Шаг 2: worker-ws (без halves) — порт _cfproxy_worker_fallback.
    if use_worker {
        let pooled = pools
            .cf_worker
            .get(dc, fallback_dst.clone(), worker_domains.clone())
            .await;
        let worker_ws = if let Some((ws, worker_domain)) = pooled {
            linfo!(
                "[{}] DC{}{} -> CF worker pool hit via {} for {}",
                label, dc, m_tag, worker_domain, fallback_dst
            );
            Some(ws)
        } else {
            let secure = !DISABLE_SECURE.load(Ordering::Relaxed);
            let query = format!("dst={}&dc={}", fallback_dst, dc);
            let path = format!("/apiws?{}", query);
            let mut found = None;
            for worker_domain in pools.cf_worker.available_domains(worker_domains.clone()).await {
                linfo!(
                    "[{}] DC{}{} -> trying CF worker {} for {}",
                    label, dc, m_tag, worker_domain, fallback_dst
                );
                match ws_connect_full_opts(
                    &worker_domain,
                    &worker_domain,
                    &path,
                    10.0,
                    None,
                    Some(secure),
                )
                .await
                {
                    Ok(ws) => {
                        found = Some(ws);
                        break;
                    }
                    Err(exc) => {
                        pools.cf_worker.report_failure(&worker_domain, &exc).await;
                        lwarn!(
                            "[{}] DC{}{} CF worker {} failed: {}",
                            label, dc, m_tag, worker_domain, exc.compact()
                        );
                    }
                }
            }
            found
        };
        if let Some(ws) = worker_ws {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            note_connection_success();
            if ws.send(relay_init).await.is_ok() {
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    None, // оригинал: splitter=None для worker
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                    cancel_token,
                    None,
                )
                .await;
                return true;
            }
            ws.close().await;
            // send failed — падаем сквозь к CF на тех же halves.
        }
    }

    // Шаг 3: cf-ws (без halves).
    if use_cf {
        if let Some((ws, _chosen_domain)) =
            cfproxy_acquire_ws(dc, is_media, ws_path, &cancel_token).await
        {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            note_connection_success();
            linfo!(" DC{}{} подключен через CF", dc, m_tag);

            if ws.send(relay_init).await.is_ok() {
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    splitter,
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                    cancel_token,
                    None,
                )
                .await;
                return true;
            }
            ws.close().await;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Client serving — порт tg_ws_proxy._handle_client (dd + ee/FakeTLS).
// ---------------------------------------------------------------------------

async fn read_proxy_protocol_line(conn: &mut TcpStream) -> Option<String> {
    let mut line = Vec::with_capacity(108);
    let mut byte = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = conn.read(&mut byte).await.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
            if line.len() > 108 {
                break;
            }
        }
        Ok::<(), ()>(())
    })
    .await;
    match res {
        Ok(Ok(())) => Some(String::from_utf8_lossy(&line).to_string()),
        _ => None,
    }
}

pub async fn handle_client(
    pools: Arc<ProxyPools>,
    mut conn: TcpStream,
    cancel_token: CancellationToken,
) {
    STATS.connections_total.fetch_add(1, Ordering::Relaxed);
    STATS.connections_active.fetch_add(1, Ordering::Relaxed);
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            if STATS.connections_active.load(Ordering::Relaxed) > 0 {
                STATS.connections_active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    let _guard = ActiveGuard;

    let peer = conn
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut label = peer;

    let _ = conn.set_nodelay(true);

    let current_secret = PROXY_SECRET.read().clone();
    let secret_bytes = hex::decode(&current_secret).unwrap_or_default();

    // PROXY protocol (proxy_config.proxy_protocol в оригинале).
    if PROXY_PROTOCOL.load(Ordering::Relaxed) {
        match read_proxy_protocol_line(&mut conn).await {
            Some(line) => {
                let text = line.trim().to_string();
                if text.starts_with("PROXY ") {
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if parts.len() >= 6 {
                        label = format!("{}:{}", parts[2], parts[4]);
                    }
                    ldebug!("[{}] PROXY protocol: {}", label, text);
                } else {
                    ldebug!("[{}] expected PROXY header, got: {:?}", label, &text[..text.len().min(60)]);
                }
            }
            None => {
                ldebug!("[{}] disconnected during PROXY header", label);
                return;
            }
        }
    }

    // FakeTLS (ee-secret): первый байт решает всё — как _read_client_init.
    let masking = FAKE_TLS_DOMAIN.read().clone();
    if !masking.is_empty() {
        let mut first = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut first)).await
        {
            Ok(Ok(_)) => {}
            _ => {
                ldebug!("[{}] client disconnected before handshake", label);
                return;
            }
        }
        if first[0] == faketls::TLS_RECORD_HANDSHAKE {
            match faketls::server_handshake(conn, first[0], &secret_bytes, &masking, &label).await
            {
                Some(plain) => {
                    serve_core(
                        &pools,
                        plain.read,
                        plain.write,
                        label,
                        secret_bytes,
                        cancel_token,
                    )
                    .await;
                }
                None => {}
            }
            return;
        } else {
            ldebug!("[{}] non-TLS byte 0x{:02X} -> HTTP redirect", label, first[0]);
            let redirect = format!(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                masking
            );
            let _ = conn.write_all(redirect.as_bytes()).await;
            return;
        }
    }

    let (conn_read, conn_write) = tokio::io::split(conn);
    serve_core(
        &pools,
        conn_read,
        conn_write,
        label,
        secret_bytes,
        cancel_token,
    )
    .await;
}

/// Ядро обслуживания соединения: 64-байтный handshake → маршрут → bridge.
/// Generic над транспортом (TcpStream-halves или FakeTLS-duplex-halves).
async fn serve_core<R, W>(
    pools: &ProxyPools,
    mut conn_read: R,
    mut conn_write: W,
    label: String,
    secret_bytes: Vec<u8>,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // 64-байтный handshake
    let mut handshake = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(10), conn_read.read_exact(&mut handshake)).await
    {
        Ok(Ok(_)) => {}
        _ => {
            ldebug!("[{}] client disconnected before handshake", label);
            return;
        }
    }

    if is_http_transport(&handshake) {
        STATS.connections_http_reject.fetch_add(1, Ordering::Relaxed);
        let _ = conn_write
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
            .await;
        let _ = conn_write.shutdown().await;
        return;
    }

    // _try_handshake: key = SHA256(prekey + secret).
    let clt_dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let clt_dec_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut hash_dec = Sha256::new();
    hash_dec.update(clt_dec_prekey);
    hash_dec.update(&secret_bytes);
    let mut clt_decryptor = new_aes_ctr(&hash_dec.finalize(), clt_dec_iv);

    let mut decrypted = handshake;
    clt_decryptor.xor(&mut decrypted);

    let proto_tag = &decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4];
    let proto = LittleEndian::read_u32(proto_tag);
    if !valid_proto(proto) {
        STATS.connections_bad.fetch_add(1, Ordering::Relaxed);
        // Клиент со старым секретом (осталась старая запись прокси в TG, его
        // «автопереключение») шлёт десятки тысяч подключений: лог на каждое
        // забивал буфер и грел CPU. Пишем не чаще раза в 10s со счётчиком.
        static BAD_LOGGED: AtomicI32 = AtomicI32::new(0);
        static BAD_LAST: parking_lot::Mutex<f64> = parking_lot::Mutex::new(f64::NEG_INFINITY);
        let suppressed = BAD_LOGGED.fetch_add(1, Ordering::Relaxed);
        let now_t = now_monotonic();
        let mut last = BAD_LAST.lock();
        if now_t - *last >= 10.0 {
            *last = now_t;
            BAD_LOGGED.store(0, Ordering::Relaxed);
            drop(last);
            lwarn!(
                "[{}] bad handshake (wrong secret or proto){} — в Telegram, вероятно, старая запись прокси со старым секретом",
                label,
                if suppressed > 0 { format!(", ещё {} за 10s", suppressed) } else { String::new() }
            );
        }
        return;
    }

    let dc_raw = LittleEndian::read_u16(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]) as i16;
    let mut dc = dc_raw as i32;
    if dc < 0 {
        dc = -dc;
    }
    let is_media = dc_raw < 0;

    // Test DC: proxy_config.force_test_dc или dc >= 10000.
    let mut is_test_dc = FORCE_TEST_DC.load(Ordering::Relaxed) || dc >= 10000;
    if dc >= 10000 {
        linfo!("[{}] test DC{} -> DC{}", label, dc, dc - 10000);
        dc -= 10000;
    }
    // force_test_dc тянет весь трафик на тестовые IP/путь.
    if FORCE_TEST_DC.load(Ordering::Relaxed) {
        is_test_dc = true;
    }
    let m_tag = if is_media { " media" } else { "" };

    let proto_int = proto; // u32 tag; MsgSplitter маппит через proto_tag_to_type
    let dc_idx = if is_media { -dc } else { dc };

    ldebug!(
        "[{}] handshake ok: DC{}{} proto=0x{:08X}{}",
        label,
        dc,
        m_tag,
        proto_int,
        if is_test_dc { " test" } else { "" }
    );

    // Сети нет (Android сообщил onLost): попытки заведомо провалятся и только
    // накопят блокировки. Закрываем сразу — TG переподключится, когда сеть
    // появится.
    if !net_available() {
        ldebug!("[{}] DC{}{} нет сети -> закрываю без попыток", label, dc, m_tag);
        return;
    }
    // Эпоха сети на момент начала: провалы, случившиеся уже после смены сети,
    // в блокировки не пишем.
    let epoch = net_epoch();

    // relayInit генерация (1-в-1 c Go + RESERVED из utils.py).
    let mut relay_init = [0u8; 64];
    loop {
        rand::thread_rng().fill_bytes(&mut relay_init);
        if relay_init[0] == RESERVED_FIRST_BYTE {
            continue;
        }
        if is_reserved_start(&relay_init[..4]) {
            continue;
        }
        if relay_init[4] == 0 && relay_init[5] == 0 && relay_init[6] == 0 && relay_init[7] == 0 {
            continue;
        }
        break;
    }

    let mut tg_dec_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        tg_dec_prekey_and_iv[i] = relay_init[8 + 47 - i];
    }

    let mut tg_encryptor = new_aes_ctr(&relay_init[8..40], &relay_init[40..56]);
    let tg_decryptor = new_aes_ctr(&tg_dec_prekey_and_iv[..32], &tg_dec_prekey_and_iv[32..]);

    let mut dc_bytes = [0u8; 2];
    LittleEndian::write_u16(&mut dc_bytes, dc_idx as u16);

    let mut tail_plain = [0u8; 8];
    tail_plain[0..4].copy_from_slice(proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_bytes);
    rand::thread_rng().fill_bytes(&mut tail_plain[6..8]);

    let mut encrypted_full = relay_init;
    tg_encryptor.xor(&mut encrypted_full);

    let mut keystream_tail = [0u8; 8];
    for i in 0..8 {
        keystream_tail[i] = encrypted_full[56 + i] ^ relay_init[56 + i];
        relay_init[56 + i] = tail_plain[i] ^ keystream_tail[i];
    }

    // clt_encryptor: prekey/iv = reverse(client_dec_prekey_iv), key=SHA256+secret.
    let mut clt_enc_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        clt_enc_prekey_and_iv[i] = handshake[8 + 47 - i];
    }
    let mut hash_enc = Sha256::new();
    hash_enc.update(&clt_enc_prekey_and_iv[..32]);
    hash_enc.update(&secret_bytes);
    let clt_encryptor = new_aes_ctr(&hash_enc.finalize(), &clt_enc_prekey_and_iv[32..]);

    let dc_key = DcKey::new(dc, is_media, is_test_dc);
    let now = now_monotonic();
    let ws_path = ws_path_for(is_test_dc);

    let target_opt = resolve_configured_target(dc, is_media);
    let dc_configured = target_opt.is_some();
    let target = target_opt.unwrap_or_default();

    let blacklisted = WS_BLACKLIST.read().get(&dc_key).map(|until| now < *until).unwrap_or(false);
    let ip_cooldown_active = if target.is_empty() {
        false
    } else {
        IP_FAIL_UNTIL.read().get(&target).map(|until| now < *until).unwrap_or(false)
            || direct_bad_active(&target)
    };
    let is_any_cf_fallback =
        CFPROXY_ENABLED.load(Ordering::Relaxed) || !CF_WORKER_DOMAINS.read().is_empty();
    // Медиа этого DC в текущем типе сети недавно «душили» на прямом WS.
    let breaker_left = if is_media && !is_test_dc {
        breaker_blocked_for(dc_key)
    } else {
        0.0
    };

    // Fallback если DC нет в конфиге, WS в чёрном списке или IP на cooldown —
    // порт ветки из _handle_client оригинала.
    let mut pooled_ws: Option<RawWebSocket> = None;
    let mut use_pooled_direct = false;
    if !dc_configured
        || blacklisted
        || breaker_left > 0.0
        || (ip_cooldown_active && is_any_cf_fallback)
    {
        if !dc_configured {
            linfo!("[{}] DC{} not in config -> fallback", label, dc);
        } else if blacklisted {
            linfo!("[{}] DC{}{} WS blacklisted -> fallback", label, dc, m_tag);
        } else if breaker_left > 0.0 {
            linfo!(
                "[{}] DC{}{} медиа душили на прямом WS ({}) -> fallback ещё {:.0}s",
                label, dc, m_tag,
                net_kind_name(NET_KIND.load(Ordering::Relaxed)),
                breaker_left
            );
        } else {
            // Шанс пулу при случайном таймауте: пробуем забрать готовый WS.
            if !is_test_dc {
                let domains = ws_domains(dc, is_media);
                pooled_ws = pools
                    .ws
                    .get(dc, is_media, target.clone(), domains)
                    .await;
            }
            if pooled_ws.is_none() {
                linfo!(
                    "[{}] DC{}{} WS connect to {} was timed out -> fallback",
                    label, dc, m_tag, target
                );
            } else {
                linfo!(
                    "[{}] DC{}{} WS connect to {} was timed out, but pool hit -> using WS",
                    label, dc, m_tag, target
                );
                use_pooled_direct = true;
            }
        }

        if !use_pooled_direct {
            let splitter = MsgSplitter::new(&relay_init, proto_int);
            let ok = do_fallback(
                pools,
                conn_read,
                conn_write,
                &relay_init,
                label.clone(),
                dc,
                is_test_dc,
                is_media,
                splitter,
                &clt_decryptor,
                &clt_encryptor,
                &tg_encryptor,
                &tg_decryptor,
                cancel_token,
            )
            .await;
            if !ok {
                lwarn!("[{}] DC{}{} no fallback available", label, dc, m_tag);
                note_connection_failure(pools).await;
            }
            return;
        }
    }

    let fail_until = DC_FAIL_UNTIL.read().get(&dc_key).copied().unwrap_or(0.0);
    let ws_timeout = if now < fail_until {
        WS_FAIL_TIMEOUT
    } else {
        WS_DIRECT_TIMEOUT
    };

    let domains = ws_domains(dc, is_media);
    // pooled_ws уже может держать WS из cooldown-ветки.
    let mut ws_opt = pooled_ws;
    let mut ws_failed_redirect = false;
    let mut ws_timed_out = false;
    let mut all_redirects = true;

    if ws_opt.is_none() && !is_test_dc {
        ws_opt = pools
            .ws
            .get(dc, is_media, target.clone(), domains.clone())
            .await;
        if ws_opt.is_some() {
            linfo!("[{}] DC{}{} -> pool hit via {}", label, dc, m_tag, target);
        }
    }

    // Пул уже выяснил, что работает только fronting — не тратим ws_timeout на
    // заведомо режущийся прямой SNI.
    if ws_opt.is_none() && !is_test_dc && ws_pool_fronting_first() && !fronting_bad_active() {
        if let Some(d) = domains.first() {
            ws_opt = connect_fronted(&target, d, ws_path).await;
            if ws_opt.is_some() {
                all_redirects = false;
                linfo!("[{}] DC{}{} -> fronted wss://{} via {}", label, dc, m_tag, d, target);
            }
        }
    }

    if ws_opt.is_none() {
        for domain in &domains {
            let url = format!("wss://{}{} via {}", domain, ws_path, target);
            linfo!("[{}] DC{}{} -> {}", label, dc, m_tag, url);
            let allow_fronting = !is_test_dc && !ws_pool_fronting_first();
            match connect_direct_hedged(&target, domain, ws_path, ws_timeout, allow_fronting).await {
                DirectOutcome::Direct(ws) => {
                    all_redirects = false;
                    // Fronting-first мог остаться от прошлой сети/сбоя: прямой путь
                    // работает — не тратим fronting-таймаут на каждом коннекте.
                    if ws_pool_fronting_first() {
                        set_ws_pool_fronting_first(false);
                    }
                    ws_opt = Some(ws);
                    break;
                }
                DirectOutcome::Fronted(ws) => {
                    all_redirects = false;
                    linfo!("[{}] DC{}{} -> fronted wss://{} via {}", label, dc, m_tag, domain, target);
                    ws_opt = Some(ws);
                    break;
                }
                DirectOutcome::Failed(WsError::Handshake(h)) if h.is_redirect() => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    ws_failed_redirect = true;
                    lwarn!(
                        "[{}] DC{}{} got {} from {} -> {}",
                        label,
                        dc,
                        m_tag,
                        h.status_code,
                        domain,
                        if h.location.is_empty() { "?" } else { &h.location }
                    );
                    continue;
                }
                DirectOutcome::Failed(WsError::Handshake(h)) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    all_redirects = false;
                    lwarn!(
                        "[{}] DC{}{} WS handshake: {}",
                        label, dc, m_tag, h.status_line
                    );
                    continue;
                }
                DirectOutcome::Failed(WsError::Timeout) => {
                    // Fronting уже пробовался внутри connect_direct_hedged.
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    lwarn!(
                        "[{}] DC{}{} WS connect timed out via {}",
                        label, dc, m_tag, domain
                    );
                    ws_timed_out = true;
                    break;
                }
                DirectOutcome::Failed(exc) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    all_redirects = false;
                    lwarn!(
                        "[{}] DC{}{} WS connect failed: {}",
                        label, dc, m_tag, exc.compact()
                    );
                    continue;
                }
            }
        }
    } else {
        all_redirects = false;
    }

    // WS failed -> fallback (порт оригинала 1-в-1).
    if ws_opt.is_none() {
        // Сеть пропала или сменилась, пока шла попытка: провал говорит о сети,
        // а не о маршруте — в блокировки не пишем.
        let counts = failure_counts(epoch);
        if !counts {
            linfo!(
                "[{}] DC{}{} WS не удался, но сеть сменилась/пропала — не учитываю",
                label, dc, m_tag
            );
        }
        if counts && ws_timed_out && !target.is_empty() {
            let strikes = {
                let mut m = IP_TIMEOUT_STRIKES.write();
                let e = m.entry(target.clone()).or_insert((0, 0.0));
                if now - e.1 > IP_FAIL_STRIKE_WINDOW {
                    e.0 = 0;
                }
                e.0 += 1;
                e.1 = now;
                e.0
            };
            // На LTE — с первого таймаута и на 5 минут (как в 1.3.1), на Wi-Fi —
            // после 2 подряд и на 2 минуты. Плюс память по типу сети.
            let (need_strikes, cooldown, remember) = ip_fail_policy();
            if strikes >= need_strikes {
                IP_FAIL_UNTIL
                    .write()
                    .insert(target.clone(), now + cooldown);
                direct_bad_mark(&target, now + remember);
                linfo!(
                    "[{}] DC{}{} WS connect to {} timed out ({}x), cooldown for {}s ({})",
                    label, dc, m_tag, target, strikes, cooldown as i64,
                    net_kind_name(NET_KIND.load(Ordering::Relaxed))
                );
            } else {
                linfo!(
                    "[{}] DC{}{} WS connect to {} timed out ({}/{}), no cooldown yet",
                    label, dc, m_tag, target, strikes, need_strikes
                );
            }
        }

        if !counts {
            // ничего не записываем
        } else if ws_failed_redirect && all_redirects {
            WS_BLACKLIST.write().insert(dc_key, now + WS_BLACKLIST_TTL);
            lwarn!("[{}] DC{}{} blacklisted for WS (all 302)", label, dc, m_tag);
        } else if ws_failed_redirect {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
        } else {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
            linfo!(
                "[{}] DC{}{} WS failed for {}s",
                label, dc, m_tag, DC_FAIL_COOLDOWN as i64
            );
        }

        let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
        let ok = do_fallback(
            pools,
            conn_read,
            conn_write,
            &relay_init,
            label.clone(),
            dc,
            is_test_dc,
            is_media,
            splitter_fb,
            &clt_decryptor,
            &clt_encryptor,
            &tg_encryptor,
            &tg_decryptor,
            cancel_token,
        )
        .await;
        if ok {
            linfo!("[{}] DC{}{} fallback closed", label, dc, m_tag);
        } else {
            lwarn!("[{}] DC{}{} no fallback available", label, dc, m_tag);
            note_connection_failure(pools).await;
        }
        return;
    }

    note_connection_success();
    if !target.is_empty() {
        IP_FAIL_UNTIL.write().remove(&target);
        IP_TIMEOUT_STRIKES.write().remove(&target);
        if failure_counts(epoch) && direct_bad_clear(&target) {
            linfo!("[{}] прямой WS к {} снова работает ({})", label, target, net_kind_name(NET_KIND.load(Ordering::Relaxed)));
        }
    }
    pools.ws.report_success(dc, is_media).await;
    STATS.connections_ws.fetch_add(1, Ordering::Relaxed);

    let splitter = MsgSplitter::new(&relay_init, proto_int);
    if splitter.is_some() {
        ldebug!(
            "[{}] MsgSplitter activated for proto 0x{:08X}",
            label, proto_int
        );
    }

    // send direct init (с retry на свежий WS как мобильное улучшение).
    let mut ws = ws_opt.take().unwrap();
    let mut send_ok = ws.send(&relay_init).await.is_ok();
    if send_ok {
        ldebug!(" direct relayInit sent DC{}{}", dc, m_tag);
    } else {
        lwarn!(" direct relayInit write fail DC{}{}: closed", dc, m_tag);
        ws.close().await;

        if failure_counts(epoch) {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
        }

        lwarn!(" direct retry fresh ws DC{}{}", dc, m_tag);
        let (retry_ws, retry_failed_redirect, retry_all_redirects) =
            connect_direct_ws(&target, &domains, ws_timeout, ws_path).await;
        match retry_ws {
            None => {
                if retry_failed_redirect && retry_all_redirects && failure_counts(epoch) {
                    WS_BLACKLIST.write().insert(dc_key, now_monotonic() + WS_BLACKLIST_TTL);
                    lwarn!(" DC{}{} заблокирован (302)", dc, m_tag);
                }
                lwarn!(" direct fallback DC{}{}", dc, m_tag);
                let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
                do_fallback(
                    pools,
                    conn_read,
                    conn_write,
                    &relay_init,
                    label,
                    dc,
                    is_test_dc,
                    is_media,
                    splitter_fb,
                    &clt_decryptor,
                    &clt_encryptor,
                    &tg_encryptor,
                    &tg_decryptor,
                    cancel_token,
                )
                .await;
                return;
            }
            Some(rws) => {
                if rws.send(&relay_init).await.is_err() {
                    lwarn!(" direct relayInit write fail DC{}{}: closed", dc, m_tag);
                    rws.close().await;
                    lwarn!(" direct fallback DC{}{}", dc, m_tag);
                    let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
                    do_fallback(
                        pools,
                        conn_read,
                        conn_write,
                        &relay_init,
                        label,
                        dc,
                        is_test_dc,
                        is_media,
                        splitter_fb,
                        &clt_decryptor,
                        &clt_encryptor,
                        &tg_encryptor,
                        &tg_decryptor,
                        cancel_token,
                    )
                    .await;
                    return;
                }
                ws = rws;
                send_ok = true;
            }
        }
    }
    let _ = send_ok;

    DC_FAIL_UNTIL.write().remove(&dc_key);
    bridge_ws(
        conn_read,
        conn_write,
        ws,
        label,
        dc,
        is_media,
        splitter,
        clt_decryptor,
        clt_encryptor,
        tg_encryptor,
        tg_decryptor,
        cancel_token,
        if is_media && !is_test_dc { Some(dc_key) } else { None },
    )
    .await;
}

pub enum DirectOutcome {
    Direct(RawWebSocket),
    Fronted(RawWebSocket),
    Failed(WsError),
}

/// Прямой WS; при таймауте — fronting (как в 1.3.1, последовательно).
/// Редиректы и прочие ошибки прямого уходят наверх без fronting.
async fn connect_direct_hedged(
    target: &str,
    domain: &str,
    ws_path: &str,
    timeout: f64,
    allow_fronting: bool,
) -> DirectOutcome {
    // Some(true): DISABLE_SECURE (порт 80) относится только к CF. Без этого
    // прямой WS к Telegram шёл plain HTTP с Host: kwsN.web.telegram.org.
    let direct = ws_connect_full_opts(target, domain, ws_path, timeout, None, Some(true));
    tokio::pin!(direct);
    if !allow_fronting {
        return match direct.await {
            Ok(ws) => DirectOutcome::Direct(ws),
            Err(e) => DirectOutcome::Failed(e),
        };
    }
    // Как в 1.3.1: fronting только после таймаута прямого. Параллельный старт
    // (1.3.2) на LTE часто отдавал победу fronting'у при живом, но медленном
    // прямом пути и переключал на него все следующие соединения — хуже.
    match direct.await {
        Ok(ws) => DirectOutcome::Direct(ws),
        // Fronting на этом типе сети недавно не прошёл — не тратим на него 7s.
        Err(WsError::Timeout) if fronting_bad_active() => DirectOutcome::Failed(WsError::Timeout),
        Err(WsError::Timeout) => match connect_fronted(target, domain, ws_path).await {
            Some(ws) => DirectOutcome::Fronted(ws),
            None => DirectOutcome::Failed(WsError::Timeout),
        },
        Err(e) => DirectOutcome::Failed(e),
    }
}

// connectDirectWS — прямой перебор доменов (тихий, для retry-пути).
pub async fn connect_direct_ws(
    target: &str,
    domains: &[String],
    timeout: f64,
    ws_path: &str,
) -> (Option<RawWebSocket>, bool, bool) {
    if domains.is_empty() {
        return (None, false, false);
    }
    let mut ws_failed_redirect = false;
    let mut all_redirects = true;

    for dom in domains {
        match ws_connect_full_opts(target, dom, ws_path, timeout, None, Some(true)).await {
            Ok(ws) => return (Some(ws), ws_failed_redirect, false),
            Err(WsError::Handshake(h)) => {
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                if h.is_redirect() {
                    ws_failed_redirect = true;
                } else {
                    all_redirects = false;
                }
            }
            Err(WsError::Timeout) => {
                // Как в оригинале: таймаут прерывает перебор, all_redirects не трогаем.
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Err(_) => {
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                all_redirects = false;
            }
        }
    }
    (None, ws_failed_redirect, all_redirects)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub async fn run_proxy(
    pools: Arc<ProxyPools>,
    host: String,
    port: u16,
    dc_opt_map: HashMap<i32, String>,
    cancel_root: CancellationToken,
    listener: TcpListener,
) -> std::io::Result<()> {
    {
        let mut m = DC_OPT.write();
        *m = dc_opt_map.clone();
    }

    start_cfproxy_refresh(cancel_root.clone());

    {
        let p = pools.clone();
        let map = dc_opt_map.clone();
        tokio::spawn(async move {
            p.warmup(&map).await;
        });
    }

    linfo!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    linfo!("  TG WS Proxy запущен");
    linfo!("  Адрес: {}:{}", host, port);
    linfo!("  Target DC IPs:");
    let mut dcs: Vec<i32> = dc_opt_map.keys().copied().collect();
    dcs.sort();
    for dc in dcs {
        if let Some(ip) = dc_opt_map.get(&dc) {
            linfo!("    DC{}: {}", dc, ip);
        }
    }
    if CFPROXY_ENABLED.load(Ordering::Relaxed) {
        linfo!("  CF proxy:      enabled");
    }
    if !CF_WORKER_DOMAINS.read().is_empty() {
        linfo!(
            "  CF worker:     enabled ({})",
            CF_WORKER_DOMAINS.read().join(", ")
        );
    }
    if DISABLE_SECURE.load(Ordering::Relaxed) {
        linfo!("  No secure:     enabled (port 80 for CF proxy/worker)");
    }
    if !FAKE_TLS_DOMAIN.read().is_empty() {
        linfo!("  Fake TLS:      {}", FAKE_TLS_DOMAIN.read().clone());
    }

    let cancel_stats = cancel_root.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel_stats.cancelled() => return,
                _ = interval.tick() => {
                    linfo!(" {}", STATS.summary_ru());
                }
            }
        }
    });

    // Ошибки accept() раньше просто пропускались через `continue`: при сломанном
    // слушающем сокете цикл крутился вхолостую, а TG не мог подключиться до
    // ручного перезапуска. Теперь пауза, а после серии ошибок — пересоздание
    // сокета (как у форка Alexingin; аналог listener watchdog в Flowseal).
    let mut listener = listener;
    let mut accept_errors: u32 = 0;
    loop {
        tokio::select! {
            _ = cancel_root.cancelled() => {
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((conn, _)) => {
                        accept_errors = 0;
                        let p = pools.clone();
                        let cancel = cancel_root.child_token();
                        tokio::spawn(async move {
                            handle_client(p, conn, cancel).await;
                        });
                    }
                    Err(e) => {
                        accept_errors += 1;
                        if accept_errors == 1 || accept_errors % 20 == 0 {
                            lwarn!("accept error #{}: {}", accept_errors, e);
                        }
                        tokio::select! {
                            _ = cancel_root.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                        }
                        if accept_errors >= 10 {
                            let addr = format!("{}:{}", host, port);
                            drop(listener);
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            loop {
                                match TcpListener::bind(&addr).await {
                                    Ok(l) => {
                                        lwarn!("Listening socket restored on {}", addr);
                                        listener = l;
                                        accept_errors = 0;
                                        break;
                                    }
                                    Err(be) => {
                                        lwarn!("Re-bind {} failed: {}, retry in 2s", addr, be);
                                        tokio::select! {
                                            _ = cancel_root.cancelled() => {
                                                pools.close_all().await;
                                                return Ok(());
                                            }
                                            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    drop(listener);
    cancel_root.cancel();
    tokio::time::sleep(Duration::from_millis(100)).await;
    pools.close_all().await;
    Ok(())
}

pub fn parse_cidr_pool(cidrs_str: &str) -> HashMap<i32, String> {
    let mut result = HashMap::new();
    if cidrs_str.trim().is_empty() {
        return result;
    }
    for pair in cidrs_str.split(',') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() == 2 {
            let dc_raw = parts[0].trim();
            let ip_raw = parts[1].trim();
            if let Ok(dc) = dc_raw.parse::<i32>() {
                if !ip_raw.is_empty() {
                    if let Ok(ip) = ip_raw.parse::<std::net::IpAddr>() {
                        result.insert(dc, ip.to_string());
                    }
                }
            }
        }
    }
    result
}
