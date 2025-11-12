from dataclasses import dataclass
from typing import Optional, Union
import hashlib, json, os

from manage_meta import read_root, verify_multi_signature

JsonLike = dict
PathLike = Union[str, os.PathLike]

@dataclass
class VerifyResult:
    ok: bool
    reason: Optional[str] = None


def _as_dict(maybe_path_or_dict: Union[JsonLike, PathLike]) -> JsonLike:
    """str/Path면 JSON 파일을 읽어 dict로, 이미 dict면 그대로 반환."""
    if isinstance(maybe_path_or_dict, (str, os.PathLike, bytes)):
        path = os.fspath(maybe_path_or_dict)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return maybe_path_or_dict  # assume dict


def _normalize_signatures(meta: dict) -> dict:
    """
    manage_meta는 root.json에서 'signatures'(복수)를 사용.
    ECU 리포트/VVM에는 'signature'(단수)일 수 있으니 호환을 위해 변환.
    """
    if "signatures" not in meta and "signature" in meta:
        sig = meta["signature"]
        if isinstance(sig, dict):
            meta["signatures"] = [sig]
        elif isinstance(sig, list):
            meta["signatures"] = sig
    return meta


class Verifier:
    def quick_hash_check(self, file_path: str, expected_sha256: str):
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        got = h.hexdigest()
        if got.lower() != expected_sha256.lower():
            raise ValueError(f"sha256 mismatch: expected={expected_sha256} got={got}")

    def verify_with_meta(self, meta_in: Union[JsonLike, PathLike], image_path: str) -> VerifyResult:
        """
        meta_in: dict 또는 파일 경로 어느 쪽도 허용.
        - root 메타면 read_root()로 공개키를 파일로 내리고 verify_multi_signature() 수행
        - 비-루트 메타도 signature(s) 필드만 있으면 verify_multi_signature() 호출 가능
        이미지 해시는 Updater 단계에서 expected_sha256로 이미 빠른 검증을 함.
        """
        try:
            meta = _as_dict(meta_in)
            meta = _normalize_signatures(meta)

            mtype = meta.get("signed", {}).get("_type")
            if mtype == "root":
                key_info = read_root(meta)          # manage_meta는 dict 기대
                verify_multi_signature(meta, key_info)
            else:
                # 필요 시 비-루트에 대한 key_info 설계/확장 가능
                verify_multi_signature(meta, {})

            return VerifyResult(ok=True)
        except Exception as e:
            return VerifyResult(ok=False, reason=str(e))
