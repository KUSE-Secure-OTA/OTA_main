import os
import time
import json
import tarfile
import shutil
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

         # 3) 새로 생성된 청크들만 압축 (metrics['chunks'] 사용)
        new_chunks = split_metrics.get("chunks", [])
        chunks_archive_path = os.path.join(ROOT_DIR, "new_chunks.tar.gz")

        with tarfile.open(chunks_archive_path, "w:gz") as tar:
            for h in new_chunks:
                chunk_path = os.path.join(CHUNKS_DIR, h)
                if os.path.exists(chunk_path):
                    # 압축 안에서의 이름은 파일명만 사용 (필요하면 경로 붙여도 됨)
                    tar.add(chunk_path, arcname=h)
        print(f"[watchdog] 새 청크 압축 생성 완료: {chunks_archive_path}")
        
        chunks_archive_dst = os.path.join(self.image_dir, "new_chunks.tar.gz")
        # 이미 있으면 덮어쓰기
        if os.path.exists(chunks_archive_dst):
            os.remove(chunks_archive_dst)
        shutil.move(chunks_archive_path, chunks_archive_dst)
        print(f"[watchdog] new_chunks.tar.gz 이동 완료: {chunks_archive_dst}")
        
        
        manifests_archive_src = os.path.join(ROOT_DIR, "manifests.tar.gz")
        if os.path.exists(manifests_archive_src):
            manifests_archive_dst = os.path.join(self.image_dir, "manifests.tar.gz")
            # 이미 있으면 덮어쓰기
            if os.path.exists(manifests_archive_dst):
                os.remove(manifests_archive_dst)
            shutil.move(manifests_archive_src, manifests_archive_dst)
            print(f"[watchdog] manifests.tar.gz 이동 완료: {manifests_archive_dst}")
        else:
            print("[watchdog] 경고: manifests.tar.gz 를 찾지 못했습니다.")



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