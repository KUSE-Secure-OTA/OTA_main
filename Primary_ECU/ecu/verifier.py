from dataclasses import dataclass
from typing import Optional
import hashlib, json

# 기존 함수 연결
from manage_meta import read_root, verify_multi_signature
# 필요 시 utils.signature.* 도 여기서 사용

@dataclass
class VerifyResult:
    ok: bool
    reason: Optional[str] = None

class Verifier:
    def quick_hash_check(self, file_path: str, expected_sha256: str):
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024*1024), b""):
                h.update(chunk)
        if h.hexdigest() != expected_sha256.lower():
            raise ValueError("sha256 mismatch")

    def verify_with_meta(self, meta_path: str, image_path: str) -> VerifyResult:
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)

            # 예시: 루트 키 체인 체크 + 다중 서명 검증
            key_info = read_root(meta) if meta["signed"]["_type"] == "root" else {}
            verify_multi_signature(meta, key_info)

            # 메타에 기록된 해시와 실제 파일 해시 일치 확인(필요한 형식에 맞춰 수정)
            # 여기서는 targets[0].sha256 가정
            target_sha = (meta.get("targets") or [{}])[0].get("sha256")
            if target_sha:
                self.quick_hash_check(image_path, target_sha)

            return VerifyResult(ok=True)
        except Exception as e:
            return VerifyResult(ok=False, reason=str(e))
