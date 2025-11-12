import shutil, requests

_DEFAULT_TIMEOUT = 60
_DEFAULT_HEADERS = {"User-Agent": "PrimaryECU-Updater/1.0"}

class Transport:
    """메타/이미지 등을 원격에서 받아오는 전송 계층."""

    def fetch(self, url: str, dst_path: str) -> str:
        if url.startswith("http"):
            with requests.get(url, stream=True, timeout=_DEFAULT_TIMEOUT, headers=_DEFAULT_HEADERS) as r:
                r.raise_for_status()
                with open(dst_path, "wb") as f:
                    shutil.copyfileobj(r.raw, f)
            return dst_path
        # 필요 시: mqtt://, file:// 등 추가 스킴 구현
        raise NotImplementedError(f"unsupported url: {url}")
