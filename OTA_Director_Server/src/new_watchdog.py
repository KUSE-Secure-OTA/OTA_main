import os
import time
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import base64
import shutil
import threading
import queue
from utils.json_handler import JsonHandler
from utils.signature.pub_signature import make_payload_with_signature
from utils.signature.sub_signature import verify_signature

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

    def encode_files(self, json_path):
        with open(json_path, "rb") as files_file:
            encoded_files = base64.b64encode(files_file.read())
            return encoded_files


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, watch_dir, image_dir):
        self.watch_dir = watch_dir
        self.image_dir = image_dir
        self.json_handler = JsonHandler()

        self.event_queue = queue.Queue()
        self.processing_thread = threading.Thread(target=self.batch_process_events)
        self.processing_thread.daemon = True
        self.processing_thread.start()

    def on_created(self, event):
        if event.is_directory:
            print(f"[watchdog] New directory detected: {event.src_path}")
            self.event_queue.put(event.src_path)

    def batch_process_events(self):
        debounce_interval = 1.0  # 1초 동안 추가되는 이벤트를 수집
        while True:
            try:
                # 최초 이벤트 대기
                first = self.event_queue.get()
                dirs_to_process = {first}
                print("[queue] Waiting for additional directories...")

                # 짧은 시간 동안 추가로 들어오는 이벤트 수집
                start_time = time.time()
                while time.time() - start_time < debounce_interval:
                    try:
                        next_item = self.event_queue.get(timeout=debounce_interval)
                        dirs_to_process.add(next_item)
                    except queue.Empty:
                        break  # 더 이상 이벤트 없음

                print(f"[process] Total directories to handle: {dirs_to_process}")
                self.handle_multiple_directories(dirs_to_process)

            except Exception as e:
                print(f"[ERROR] Event processing failed: {e}")

    def handle_multiple_directories(self, dir_paths):
        # image meta data
        all_result = {}
        max_version = "0.0.0"

        for dir_path in dir_paths:
            folder_name = os.path.basename(dir_path)
            print(f"[processing] {folder_name}")

            # JSON 변환 결과를 dict로 받아옴
            temp_output = f"/tmp/{folder_name}_temp.json"
            self.json_handler.target_to_json(dir_path, temp_output)

            with open(temp_output, "r", encoding="utf-8") as f:
                data = json.load(f)

            version = data["version"]
            if self.json_handler.compare_versions(version, max_version):
                max_version = version

            # 각 디렉터리별 항목 추가
            for k, v in data.items():
                if k != "version":
                    all_result[k] = v

            # 파일 복사
            dest_path = os.path.join(self.image_dir, folder_name)
            try:
                if os.path.exists(dest_path):
                    shutil.rmtree(dest_path)
                shutil.copytree(dir_path, dest_path)
                print(f"[copy] {dir_path} → {dest_path}")
            except Exception as e:
                print(f"[ERROR] Copy failed: {e}")

        # 최종 JSON 저장
        final_output = "../data/target_new.json"
        with open(final_output, "w", encoding="utf-8") as f:
            json.dump({"version": max_version, **all_result}, f, indent=4, ensure_ascii=False)
        print(f"[output] JSON updated: {final_output}")

        # Director meta data
        all_result = {}
        max_version = "0.0.0"

        for dir_path in dir_paths:
            folder_name = os.path.basename(dir_path)
            print(f"[processing] {folder_name}")

            # JSON 변환 결과를 dict로 받아옴
            temp_inventory_output = f"/tmp/{folder_name}_inventory_temp.json"
            self.json_handler.target_to_inventory_json(dir_path, temp_inventory_output)

            with open(temp_inventory_output, "r", encoding="utf-8") as f:
                data = json.load(f)

            version = data["version"]
            if self.json_handler.compare_versions(version, max_version):
                max_version = version

            # 각 디렉터리별 항목 추가
            for k, v in data.items():
                if k != "version":
                    all_result[k] = v

            # 파일 복사
            dest_path = os.path.join(self.image_dir, folder_name)
            try:
                if os.path.exists(dest_path):
                    shutil.rmtree(dest_path)
                shutil.copytree(dir_path, dest_path)
                print(f"[copy] {dir_path} → {dest_path}")
            except Exception as e:
                print(f"[ERROR] Copy failed: {e}")

        # 최종 JSON 저장
        final_output = "../../OTA_Director_director/src/data/target_new.json"
        with open(final_output, "w", encoding="utf-8") as f:
            json.dump({"version": max_version, **all_result}, f, indent=4, ensure_ascii=False)
        print(f"[output] JSON updated: {final_output}")

if __name__ == "__main__":
    # 감시할 디렉토리 설정
    WATCH_DIR = "../src_add"  # 감시할 폴더 경로
    IMAGE_DIR = "../Image_Repo"

    # 파일 처리 객체 생성 및 MQTT 연결
    file_handler = FileHandler(WATCH_DIR, IMAGE_DIR)

    # MQTT 및 파일 감시 시작
    file_handler.start_watching()

    try:
        while True:
            print("-")
            time.sleep(1)
    except KeyboardInterrupt:
        file_handler.stop_watching()
        file_handler.observer.join()