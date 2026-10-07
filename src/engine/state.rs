//! 接続記録・通信量・ログの共有状態。

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::rules::{Proto, RuleSet};

const MAX_CONN_RECORDS: usize = 2000;
const MAX_LOG_LINES: usize = 1000;

#[derive(Default)]
pub struct Counters {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Connecting,
    Open,
    Closed,
    Blocked,
    Failed(String),
}

impl ConnState {
    /// 接続中・通信中（まだ終わっていない）
    pub fn is_active(&self) -> bool {
        matches!(self, ConnState::Connecting | ConnState::Open)
    }
}

pub struct ConnRecord {
    pub id: u64,
    pub time: String,
    pub proto: Proto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub process: Option<String>,
    pub rule_line: Option<usize>,
    pub action: String,
    pub counters: Arc<Counters>,
    pub state: ConnState,
}

#[derive(Default)]
pub struct Shared {
    pub rules: ArcSwap<RuleSet>,
    pub conns: Mutex<VecDeque<ConnRecord>>,
    pub logs: Mutex<VecDeque<String>>,
    pub active: AtomicUsize,
    pub total: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    next_id: AtomicU64,
}

impl Shared {
    pub(super) fn open_conn(&self, id: u64) -> ActiveConnection<'_> {
        self.update_conn(id, |record| record.state = ConnState::Open);
        self.active.fetch_add(1, Ordering::Relaxed);
        ActiveConnection { shared: self, id, state: ConnState::Closed }
    }

    pub fn log(&self, msg: impl Into<String>) {
        let mut logs = self.logs.lock();
        if logs.len() >= MAX_LOG_LINES {
            logs.pop_front();
        }
        let line = format!("{} {}", now_hms(), msg.into());
        crate::config::append_log(&line);
        logs.push_back(line);
    }

    /// 接続表の集計（状態ごとの件数と、直近の失敗）をログに残す。停止時の調査用
    pub(super) fn log_conn_summary(&self) {
        let lines = {
            let conns = self.conns.lock();
            let mut by_state: std::collections::BTreeMap<String, usize> = Default::default();
            for c in conns.iter() {
                let key = match &c.state {
                    ConnState::Failed(_) => "失敗".to_string(),
                    s => format!("{s:?}"),
                };
                *by_state.entry(format!("{} {key}", c.proto)).or_default() += 1;
            }
            let mut v = vec![format!(
                "接続の集計（直近 {} 件）: {}",
                conns.len(),
                by_state.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>().join(", ")
            )];
            let failed = conns.iter().rev().filter_map(|c| match &c.state {
                ConnState::Failed(m) => Some((c, m)),
                _ => None,
            });
            v.extend(failed.take(30).map(|(c, m)| {
                format!(
                    "  失敗 {} {} {} → {} [{}] {} 行={:?}: {m}",
                    c.time,
                    c.proto,
                    c.src,
                    c.dst,
                    c.process.as_deref().unwrap_or("?"),
                    c.action,
                    c.rule_line
                )
            }));
            v
        };
        for l in lines {
            self.log(l);
        }
    }

    pub(super) fn push_conn(&self, mut rec: ConnRecord) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        rec.id = id;
        self.total.fetch_add(1, Ordering::Relaxed);
        let mut conns = self.conns.lock();
        if conns.len() >= MAX_CONN_RECORDS {
            conns.pop_front();
        }
        conns.push_back(rec);
        id
    }

    /// 終わった接続を接続表から消す
    pub fn clear_finished(&self) {
        self.conns.lock().retain(|c| c.state.is_active());
    }

    pub(super) fn update_conn(&self, id: u64, f: impl FnOnce(&mut ConnRecord)) {
        let mut conns = self.conns.lock();
        if let Some(r) = conns.iter_mut().rev().find(|r| r.id == id) {
            f(r);
        }
    }
}

/// 通常終了・エラー・タスクのキャンセルで、接続状態と接続数を必ず片付ける。
pub(super) struct ActiveConnection<'a> {
    shared: &'a Shared,
    id: u64,
    state: ConnState,
}

impl ActiveConnection<'_> {
    pub(super) fn finish(mut self, result: io::Result<()>) {
        use io::ErrorKind::*;
        self.state = match result {
            Ok(()) => ConnState::Closed,
            Err(e) if matches!(e.kind(), ConnectionReset | ConnectionAborted | BrokenPipe | TimedOut | UnexpectedEof | NotConnected) => {
                ConnState::Closed
            }
            Err(e) => ConnState::Failed(e.to_string()),
        };
    }
}

impl Drop for ActiveConnection<'_> {
    fn drop(&mut self) {
        let state = std::mem::replace(&mut self.state, ConnState::Closed);
        self.shared.update_conn(self.id, |record| record.state = state);
        self.shared.active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn now_hms() -> String {
    let t = unsafe {
        let mut t = std::mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut t);
        t
    };
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(shared: &Shared) -> u64 {
        shared.push_conn(ConnRecord {
            id: 0,
            time: String::new(),
            proto: Proto::Tcp,
            src: "127.0.0.1:1000".parse().unwrap(),
            dst: "127.0.0.1:2000".parse().unwrap(),
            process: None,
            rule_line: None,
            action: String::new(),
            counters: Arc::default(),
            state: ConnState::Connecting,
        })
    }

    #[test]
    fn relay_completion_classifies_errors_and_releases_count() {
        use io::ErrorKind::*;
        let cases = [
            None,
            Some(ConnectionReset),
            Some(ConnectionAborted),
            Some(BrokenPipe),
            Some(TimedOut),
            Some(UnexpectedEof),
            Some(NotConnected),
            Some(PermissionDenied),
        ];
        for error in cases {
            let shared = Shared::default();
            let connection = shared.open_conn(record(&shared));
            assert_eq!(shared.active.load(Ordering::Relaxed), 1);
            assert_eq!(shared.conns.lock()[0].state, ConnState::Open);
            connection.finish(error.map_or(Ok(()), |kind| Err(io::Error::new(kind, "test"))));
            let expected = if error == Some(PermissionDenied) { ConnState::Failed("test".into()) } else { ConnState::Closed };
            assert_eq!(shared.conns.lock()[0].state, expected);
            assert_eq!(shared.active.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn cancelled_relay_closes_record_and_releases_count() {
        let shared = Arc::new(Shared::default());
        let id = record(&shared);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task_shared = shared.clone();
        let task = tokio::spawn(async move {
            let _connection = task_shared.open_conn(id);
            tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        rx.await.unwrap();
        assert_eq!(shared.active.load(Ordering::Relaxed), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(shared.active.load(Ordering::Relaxed), 0);
        assert_eq!(shared.conns.lock()[0].state, ConnState::Closed);
    }

    #[test]
    fn evicted_record_does_not_prevent_connection_cleanup() {
        let shared = Shared::default();
        let first = record(&shared);
        let connection = shared.open_conn(first);
        for _ in 0..MAX_CONN_RECORDS {
            record(&shared);
        }
        assert_eq!(shared.conns.lock().len(), MAX_CONN_RECORDS);
        assert!(shared.conns.lock().iter().all(|record| record.id != first));
        drop(connection);
        assert_eq!(shared.active.load(Ordering::Relaxed), 0);
        assert_eq!(shared.total.load(Ordering::Relaxed), (MAX_CONN_RECORDS + 1) as u64);
    }
}
