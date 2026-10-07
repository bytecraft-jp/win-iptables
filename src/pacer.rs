//! 外への新規 TCP 接続の勢いを抑える。
//!
//! ipstack はアプリからの接続要求をその場で受け付けるので、開始直後などにアプリの接続が一斉に
//! 外へ出る。家庭用ルーターの「IP フラッド検出」などはこれを攻撃とみなし、PC の IPv4 をしばらく止める。
//! 1 秒あたりの新規接続数（トークンバケット）と、接続中の同時数に上限を設けて、外へ出す速さをならす。
//! あわせて、つながらなかった宛先への再試行はしばらく外へ出さずに失敗させる（アプリの再試行の殺到を防ぐ）

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{Semaphore, SemaphorePermit};

/// 1 秒あたり `rate` 件、まとめて最大 `burst` 件まで。`rate` が 0 なら制限しない
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    /// (残りトークン, 最後に補充した時刻)。残りは負にもなる（先の枠を予約している）
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    pub fn new(rate: u32, burst: u32) -> Self {
        let burst = burst.max(1) as f64;
        Self { rate: rate as f64, burst, state: Mutex::new((burst, Instant::now())) }
    }

    /// 1 件分の枠を予約し、使えるまでの待ち時間を返す
    fn reserve(&self, now: Instant) -> Duration {
        if self.rate <= 0.0 {
            return Duration::ZERO;
        }
        let mut s = self.state.lock();
        let elapsed = now.saturating_duration_since(s.1).as_secs_f64();
        s.0 = (s.0 + elapsed * self.rate).min(self.burst) - 1.0;
        s.1 = now;
        if s.0 >= 0.0 { Duration::ZERO } else { Duration::from_secs_f64(-s.0 / self.rate) }
    }

    pub async fn wait(&self) -> Duration {
        let d = self.reserve(Instant::now());
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
        d
    }
}

/// つながらなかった宛先を `hold` の間だけ覚えておく
pub struct FailCache {
    hold: Duration,
    map: Mutex<HashMap<SocketAddr, Instant>>,
}

const FAIL_CACHE_MAX: usize = 4096;

impl FailCache {
    pub fn new(hold: Duration) -> Self {
        Self { hold, map: Mutex::new(HashMap::new()) }
    }

    /// 保留中なら解除までの残り時間
    pub fn holding(&self, dst: SocketAddr, now: Instant) -> Option<Duration> {
        let until = *self.map.lock().get(&dst)?;
        (until > now).then(|| until - now)
    }

    pub fn failed(&self, dst: SocketAddr, now: Instant) {
        if self.hold.is_zero() {
            return;
        }
        let mut m = self.map.lock();
        if m.len() >= FAIL_CACHE_MAX {
            m.retain(|_, until| *until > now);
        }
        m.insert(dst, now + self.hold);
    }

    pub fn succeeded(&self, dst: SocketAddr) {
        self.map.lock().remove(&dst);
    }
}

/// 接続中の同時数の上限。0 なら制限しない
pub struct Slots(Option<Semaphore>);

impl Slots {
    pub fn new(n: u32) -> Self {
        Self((n > 0).then(|| Semaphore::new(n as usize)))
    }

    pub async fn acquire(&self) -> Option<SemaphorePermit<'_>> {
        match &self.0 {
            Some(s) => s.acquire().await.ok(),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_paces() {
        let b = TokenBucket::new(5, 3);
        let t0 = Instant::now();
        let waits: Vec<f64> = (0..6).map(|_| b.reserve(t0).as_secs_f64()).collect();
        // 3 件はすぐ、その後は 0.2 秒ずつ後ろへ並ぶ
        assert_eq!(&waits[..3], &[0.0, 0.0, 0.0]);
        for (i, w) in waits[3..].iter().enumerate() {
            assert!((w - 0.2 * (i + 1) as f64).abs() < 1e-9, "{waits:?}");
        }
        // 十分時間がたてば満タンに戻る（バースト分まで）
        assert_eq!(b.reserve(t0 + Duration::from_secs(10)), Duration::ZERO);
    }

    #[test]
    fn unlimited_bucket_never_waits() {
        let b = TokenBucket::new(0, 1);
        let t0 = Instant::now();
        assert!((0..100).all(|_| b.reserve(t0).is_zero()));
    }

    #[test]
    fn fail_cache_holds_then_releases() {
        let c = FailCache::new(Duration::from_secs(10));
        let dst: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let t0 = Instant::now();
        assert_eq!(c.holding(dst, t0), None);
        c.failed(dst, t0);
        assert_eq!(c.holding(dst, t0 + Duration::from_secs(4)), Some(Duration::from_secs(6)));
        assert_eq!(c.holding(dst, t0 + Duration::from_secs(10)), None);
        c.failed(dst, t0);
        c.succeeded(dst);
        assert_eq!(c.holding(dst, t0), None);
    }
}
