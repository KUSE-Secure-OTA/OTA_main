from dataclasses import dataclass
from typing import Optional, Union, Dict, Any
import hashlib, json, os

from manage_meta import read_root, verify_multi_signature

JsonMeta = Dict[str, Any]

@dataclass
class VerifyResult:
    ok: bool
    reason: Optional[str] = None

class Verifier:
    def __init__(self, director_root_path: str = "./root.json"):
        if not os.path.exists(director_root_path):
            raise FileNotFoundError(f"director root not found: {director_root_path}")

        with open(director_root_path, "r", encoding="utf-8") as f:
            root_meta = json.load(f)

        self.keydb = read_root(root_meta)  # 역할별 keyid / threshold 정보 포함

    # Image에서 받을 때 쓰는 거인듯. 지금은 필요 없음.
    # def quick_hash_check(self, file_path: str, expected_sha256: str):
    #     h = hashlib.sha256()
    #     with open(file_path, "rb") as f:
    #         for chunk in iter(lambda: f.read(1024 * 1024), b""):
    #             h.update(chunk)
    #     got = h.hexdigest()
    #     if got.lower() != expected_sha256.lower():
    #         raise ValueError(f"sha256 mismatch: expected={expected_sha256} got={got}")

    def verify_director_chain(self, timestamp: JsonMeta, snapshot: JsonMeta, targets: JsonMeta) -> VerifyResult:
        """
        Director의 메타데이터 순차 검증
        """
        try:
            # 역할/타입 정합성
            if timestamp["signed"].get("_type") != "timestamp":
                raise ValueError("Timestamp metadata _type mismatch")
            if snapshot["signed"].get("_type") != "snapshot":
                raise ValueError("Snapshot metadata _type mismatch")
            if targets["signed"].get("_type") != "targets":
                raise ValueError("Targets metadata _type mismatch")

            # 1) timestamp / snapshot / targets 서명 검증
            self._verify_signature(timestamp)
            self._verify_signature(snapshot)
            self._verify_signature(targets)

            # 2) 버전 연결 규칙 체크
            # timestamp → snapshot
            snap_ver_ref = next(iter(timestamp["signed"]["meta"].values()))["version"]
            if snap_ver_ref != snapshot["signed"]["version"]:
                raise ValueError(f"timestamp->snapshot version mismatch: {snap_ver_ref} != {snapshot['signed']['version']}")

            # snapshot → targets
            tgt_ver_ref = next(iter(snapshot["signed"]["meta"].values()))["version"]
            if tgt_ver_ref != targets["signed"]["version"]:
                raise ValueError(f"snapshot->targets version mismatch: {tgt_ver_ref} != {targets['signed']['version']}")

            return VerifyResult(ok=True)

        except Exception as e:
            return VerifyResult(ok=False, reason=str(e))
        
    def _verify_signature(self, meta: JsonMeta):
        verify_multi_signature(meta, self.keydb)

    # def verify_with_meta(self, meta_in: Union[JsonLike, PathLike], image_path: str) -> VerifyResult:
    #     """
    #     meta_in: dict 또는 파일 경로 어느 쪽도 허용.
    #     - root 메타면 read_root()로 공개키를 파일로 내리고 verify_multi_signature() 수행
    #     - 비-루트 메타도 signature(s) 필드만 있으면 verify_multi_signature() 호출 가능
    #     이미지 해시는 Updater 단계에서 expected_sha256로 이미 빠른 검증을 함.
    #     """
    #     try:
    #         meta = _as_dict(meta_in)
    #         meta = _normalize_signatures(meta)

    #         mtype = meta.get("signed", {}).get("_type")
    #         if mtype == "root":
    #             key_info = read_root(meta)          # manage_meta는 dict 기대
    #             verify_multi_signature(meta, key_info)
    #         else:
    #             # 필요 시 비-루트에 대한 key_info 설계/확장 가능
    #             verify_multi_signature(meta, {})

    #         return VerifyResult(ok=True)
    #     except Exception as e:
    #         return VerifyResult(ok=False, reason=str(e))