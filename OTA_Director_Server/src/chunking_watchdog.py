import os
import time
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils.fastcdc_chunking import ensure_dirs, split_all

ROOT_DIR          = '../src_add'
WATCH_DIR         = os.path.join(ROOT_DIR, 'stage')
CHUNKS_DIR        = os.path.join(ROOT_DIR, 'chunks_storage')
MANIFESTS_DIR     = os.path.join(ROOT_DIR, 'manifests')
REASSEMBLED_DIR   = os.path.join(ROOT_DIR, 'reassembled_oci')
MERGED_ROOTFS_DIR = os.path.join(REASSEMBLED_DIR, '_merged_rootfs')

class FileHandler:
    def __init__(self, watch_dir, image_dir):
        self.WATCH_DIR = watch_dir
        self.IMAGE_DIR = image_dir

        # Set the watchdog
        self.observer = Observer()
        self.event_handler = FileChangeHandler(self.WATCH_DIR, self.IMAGE_DIR)
        self.observer.schedule(self.event_handler, self.WATCH_DIR, recursive=False)

    def start_watching(self):
        print(f"Watching directory: {self.WATCH_DIR}")
        self.observer.start()
    
    def stop_watching(self):
        self.observer.stop()

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, watch_dir, image_dir):
        self.watch_dir = watch_dir
        self.image_dir = image_dir

    def on_created(self, event):
        #if event.is_directory:
        new_dir_path = event.src_path
        print(f"[watchdog] New directory detected: {new_dir_path}")

        # FastCDC 분할 수행
        ensure_dirs(CHUNKS_DIR, MANIFESTS_DIR, REASSEMBLED_DIR, MERGED_ROOTFS_DIR)
        split_metrics, split_time = split_all(new_dir_path)
        # print(f"[watchdog] FastCDC 분할 완료: {split_metrics['sha256']} {split_metrics['sha512']}, 시간: {split_time:.2f}초")

        output_json_path = os.path.join(self.image_dir, "target_new.json")
        with open(output_json_path, "w") as fp:
            json.dump(split_metrics, fp, indent=4)

        print(f"[watchdog] target_new.json 생성 완료: {output_json_path}")

if __name__ == "__main__":
    IMAGE_DIR = "../Image_Repo"

    file_handler = FileHandler(WATCH_DIR, IMAGE_DIR)
    file_handler.start_watching()

    try:
        while True:
            print("-")
            time.sleep(1)
    except KeyboardInterrupt:
        file_handler.stop_watching()
        file_handler.observer.join()