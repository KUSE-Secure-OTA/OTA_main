# utils/metrics.py
import os
import sys
import time
import threading
from datetime import datetime
from contextlib import contextmanager

import psutil


def _now_iso():
    # 후처리/정렬 쉬운 ISO 포맷
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

def _entry_name():
    # 실행 엔트리 파일명 기반
    base = os.path.basename(sys.argv[0] or "unknown")
    name, _ = os.path.splitext(base)
    return name or "unknown"

def _metrics_format():
    fmt = os.environ.get("OTA_METRICS_FORMAT", "tsv").strip().lower()
    return "csv" if fmt == "csv" else "tsv"

def _delimiter():
    return "," if _metrics_format() == "csv" else "\t"

def _escape_field(val: str) -> str:
    """
    TSV/CSV 후처리 안전을 위해 최소한의 이스케이프 처리.
    - TSV: 탭/개행 제거
    - CSV: 콤마/개행/따옴표 포함 시 RFC4180 스타일로 감싸기
    """
    s = "" if val is None else str(val)
    s = s.replace("\r", " ").replace("\n", " ")

    if _metrics_format() == "tsv":
        return s.replace("\t", " ")

    # csv
    if any(ch in s for ch in [",", '"', "\n", "\r"]):
        s = s.replace('"', '""')
        return f'"{s}"'
    return s

def _metrics_path():
    # 사용자가 명시하면 그 경로 우선
    explicit = os.environ.get("OTA_METRICS_FILE", "").strip()
    if explicit:
        return explicit

    entry = _entry_name()
    ext = _metrics_format()
    # 예: metrics_Prime_ECU.tsv / metrics_uptane_Prime_ECU.tsv
    return f"./metrics_{entry}.{ext}"

_FIELDS = [
    "ts",
    "pid",
    "entry",
    "system",
    "test_case",
    "step",
    "status",
    "elapsed_ms",
    "cpu_avg_pct",
    "cpu_max_pct",
    "rss_avg_mb",
    "rss_max_mb",
    "samples",
    "err",
]

def _ensure_header(path: str):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return
    delim = _delimiter()
    header = delim.join(_FIELDS)
    with open(path, "a", encoding="utf-8") as f:
        f.write(header + "\n")

def log_run_header(system_name: str = "", test_case: str = "", extra: str = ""):
    """
    TSV/CSV에서는 run header를 '주석 라인'으로 넣으면 파서가 귀찮아집니다.
    그래서 헤더 대신, extra는 환경변수/필드(system/test_case/entry)에 담는 것을 권장합니다.
    필요 시 아래처럼 별도 라인으로 남기려면 OTA_METRICS_ALLOW_COMMENTS=1 설정 시에만 기록.
    """
    if os.environ.get("OTA_METRICS_ALLOW_COMMENTS", "0") != "1":
        return
    path = _metrics_path()
    _ensure_header(path)
    prefix = "#"  # CSV/TSV에서 주석용
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{prefix} RUN ts={_now_iso()} pid={os.getpid()} entry={_entry_name()} system={system_name} test_case={test_case} {extra}\n")


class _Sampler:
    def __init__(self, proc: psutil.Process, interval_sec: float):
        self.proc = proc
        self.interval_sec = interval_sec
        self._stop = threading.Event()
        self.cpu_samples = []
        self.rss_samples = []

    def start(self):
        # cpu_percent 초기화(첫 호출은 의미 없는 값이 될 수 있음)
        try:
            self.proc.cpu_percent(interval=None)
        except Exception:
            pass
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def stop(self):
        self._stop.set()
        self._t.join(timeout=2.0)

    def _run(self):
        while not self._stop.is_set():
            try:
                cpu = self.proc.cpu_percent(interval=None)
                rss = self.proc.memory_info().rss / (1024 * 1024)  # MB
                self.cpu_samples.append(cpu)
                self.rss_samples.append(rss)
            except Exception:
                pass
            time.sleep(self.interval_sec)

    def stats(self):
        def _avg(xs):
            return (sum(xs) / len(xs)) if xs else 0.0
        def _max(xs):
            return max(xs) if xs else 0.0

        return {
            "cpu_avg_pct": _avg(self.cpu_samples),
            "cpu_max_pct": _max(self.cpu_samples),
            "rss_avg_mb":  _avg(self.rss_samples),
            "rss_max_mb":  _max(self.rss_samples),
            "n_samples":   len(self.cpu_samples),
        }


def _write_row(row: dict):
    path = _metrics_path()
    _ensure_header(path)

    delim = _delimiter()
    line = delim.join(_escape_field(row.get(k, "")) for k in _FIELDS)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


@contextmanager
def measure(
    step: str,
    system_name: str = "",
    test_case: str = "",
    sample_interval_sec: float = 0.01,
):
    """
    단계별 측정(프로세스 기준):
    - elapsed_ms
    - CPU% 평균/최대 (샘플링 기반)
    - RSS MB 평균/최대 (샘플링 기반)
    - TSV/CSV append 기록
    """
    proc = psutil.Process(os.getpid())
    sampler = _Sampler(proc, interval_sec=sample_interval_sec)

    t0 = time.perf_counter()
    sampler.start()

    ok = True
    err = ""
    try:
        yield
    except Exception as e:
        ok = False
        err = f"{type(e).__name__}: {e}"
        raise
    finally:
        sampler.stop()
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        st = sampler.stats()

        row = {
            "ts": _now_iso(),
            "pid": os.getpid(),
            "entry": _entry_name(),
            "system": system_name,
            "test_case": test_case,
            "step": step,
            "status": "OK" if ok else "FAIL",
            "elapsed_ms": f"{elapsed_ms:.2f}",
            "cpu_avg_pct": f"{st['cpu_avg_pct']:.2f}",
            "cpu_max_pct": f"{st['cpu_max_pct']:.2f}",
            "rss_avg_mb": f"{st['rss_avg_mb']:.2f}",
            "rss_max_mb": f"{st['rss_max_mb']:.2f}",
            "samples": st["n_samples"],
            "err": err,
        }

        # 콘솔 출력도 같은 필드 순서로(디버깅/실험 편의)
        print(" ".join([f"{k}={row[k]}" for k in _FIELDS]))

        _write_row(row)
