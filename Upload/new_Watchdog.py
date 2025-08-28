import os
import time
import threading
import queue
from datetime import datetime, timedelta, timezone

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from targets import make_targets

# ===== 설정 =====
WATCH_DIR    = "."                 # 감시할 위치
PRIVATE_KEY  = "./targets.pem"     # 서명용 개인키
EXPIRES_DAYS = 30                  # 만료: 현재 UTC + 30일
OUTPUT_DIR   = "./metadata"        # 결과 저장 위치
IGNORE_SUFFIXES = {".part", ".tmp", ".swp", ".crdownload"}

# 만료 시간 계산
def utc_expires(days: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=days)
    return exp.replace(microsecond=0).isoformat().replace("+00:00", "Z")

class TargetFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.event_queue = queue.Queue()
        self.worker = threading.Thread(target=self._batch_worker, daemon=True)
        self.worker.start()
        self.version = 0

    def on_created(self, event):
        if event.is_directory:
            return
        base = os.path.basename(event.src_path)
        if base.startswith(".") or any(base.endswith(sfx) for sfx in IGNORE_SUFFIXES):
            return
        print(f"[watch] new file: {base}")
        self.event_queue.put(event.src_path)

    def _batch_worker(self):
        debounce = 0.8
        while True:
            try:
                first = self.event_queue.get()
                group = {first}
                start = time.time()
                while time.time() - start < debounce:
                    try:
                        nxt = self.event_queue.get(timeout=debounce)
                        group.add(nxt)
                    except queue.Empty:
                        break
                self._process_group(sorted(group))
            except Exception as e:
                print(f"[ERROR] worker failed: {e}")

    def _process_group(self, files: list):
        stable = []
        for p in files:
            if not os.path.exists(p):
                continue
            s0 = os.path.getsize(p); time.sleep(0.2); s1 = os.path.getsize(p)
            if s0 == s1:
                stable.append(p)
            else:
                print(f"[skip] still writing: {os.path.basename(p)}")
        if not stable:
            return

        # 새 파일 묶음 감지 → 버전 +1
        self.version += 1
        version = self.version
        expires_iso = utc_expires(EXPIRES_DAYS)

        # target 이름은 파일명 적용
        inputs = [f"{p}:{os.path.basename(p)}" for p in stable]

        out_path = os.path.join(OUTPUT_DIR, f"{version}.targets.json")
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        print(f"[build] version={version}, expires={expires_iso}")
        print(f"[build] inputs={inputs}")

        make_targets(
            inputs=inputs,
            out_path=out_path,
            version=version,
            expires=expires_iso,
            delegations=None,
            privkey_path=PRIVATE_KEY,
        )
        print(f"[ok] wrote {os.path.abspath(out_path)}")

def main():
    handler = TargetFileHandler()
    observer = Observer()
    observer.schedule(handler, WATCH_DIR, recursive=False)
    print(f"Watching directory: {os.path.abspath(WATCH_DIR)}")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
