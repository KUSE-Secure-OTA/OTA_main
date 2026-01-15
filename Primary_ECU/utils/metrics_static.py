# OTA_main/Primary_ECU/utils/metrics_static.py
import os
import sys
import time
import threading
from datetime import datetime
from contextlib import contextmanager

import psutil


def _now_iso():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

def _entry_name():
    base = os.path.basename(sys.argv[0] or "unknown")
    name, _ = os.path.splitext(base)
    return name or "unknown"

def _metrics_format():
    fmt = os.environ.get("OTA_METRICS_FORMAT", "tsv").strip().lower()
    return "csv" if fmt == "csv" else "tsv"

def _delimiter():
    return "," if _metrics_format() == "csv" else "\t"

def _escape_field(val: str) -> str:
    s = "" if val is None else str(val)
    s = s.replace("\r", " ").replace("\n", " ")
    if _metrics_format() == "tsv":
        return s.replace("\t", " ")
    if any(ch in s for ch in [",", '"', "\n", "\r"]):
        s = s.replace('"', '""')
        return f'"{s}"'
    return s

def _metrics_path():
    explicit = os.environ.get("OTA_METRICS_FILE", "").strip()
    if explicit:
        return explicit
    entry = _entry_name()
    ext = _metrics_format()
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


class _SamplerTree:
    """
    정적 검증(run_all.sh)처럼 subprocess가 많이 뜨는 케이스용:
    현재 프로세스 + 자식 프로세스(recursive) CPU/RSS 합산.
    """
    def __init__(self, proc: psutil.Process, interval_sec: float):
        self.proc = proc
        self.interval_sec = interval_sec
        self._stop = threading.Event()
        self.cpu_samples = []
        self.rss_samples = []
        self._t = None

    def start(self):
        self._prime()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def stop(self):
        self._stop.set()
        if self._t is not None:
            self._t.join(timeout=2.0)

    def _prime(self):
        # cpu_percent는 첫 호출이 의미 없는 값일 수 있어서 prime
        try:
            self.proc.cpu_percent(interval=None)
        except Exception:
            pass
        try:
            for ch in self.proc.children(recursive=True):
                try:
                    ch.cpu_percent(interval=None)
                except Exception:
                    pass
        except Exception:
            pass

    def _sample_tree(self):
        procs = []
        try:
            procs.append(self.proc)
            procs.extend(self.proc.children(recursive=True))
        except Exception:
            procs = [self.proc]

        cpu_sum = 0.0
        rss_sum = 0.0

        for p in procs:
            try:
                cpu_sum += p.cpu_percent(interval=None)
            except Exception:
                pass
            try:
                rss_sum += p.memory_info().rss / (1024 * 1024)  # MB
            except Exception:
                pass

        return cpu_sum, rss_sum

    def _run(self):
        while not self._stop.is_set():
            try:
                cpu, rss = self._sample_tree()
                self.cpu_samples.append(cpu)
                self.rss_samples.append(rss)
            except Exception:
                pass
            time.sleep(self.interval_sec)

    def stats(self):
        def _avg(xs): return (sum(xs) / len(xs)) if xs else 0.0
        def _max(xs): return max(xs) if xs else 0.0

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
def measure_static(
    step: str,
    system_name: str = "",
    test_case: str = "",
    sample_interval_sec: float = 0.2,
):
    """
    정적 검증 전용 측정(부모+자식 프로세스 트리 합산):
    - elapsed_ms
    - CPU% avg/max (샘플링 기반, tree sum)
    - RSS MB avg/max (tree sum)
    """
    proc = psutil.Process(os.getpid())
    sampler = _SamplerTree(proc, interval_sec=sample_interval_sec)

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

        print(" ".join([f"{k}={row[k]}" for k in _FIELDS]))
        _write_row(row)