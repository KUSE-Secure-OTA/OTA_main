import shutil, requests

class Transport:
    def fetch(self, url: str, dst_path: str) -> str:
        if url.startswith("http"):
            with requests.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()
                with open(dst_path, "wb") as f:
                    shutil.copyfileobj(r.raw, f)
            return dst_path
        # 이미 MQTT로 파일을 받는 구현이 있으면 같은 시그니처로 여기서 감싸주세요.
        raise NotImplementedError(f"unsupported url: {url}")
