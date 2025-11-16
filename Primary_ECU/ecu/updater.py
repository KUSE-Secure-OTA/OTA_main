from __future__ import annotations
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Dict, Any
import time

from .storage import Storage
from .transport import Transport
from .verifier import Verifier, VerifyResult
from .installer import Installer, InstallResult

class State(Enum):
    IDLE=auto(); FETCH_META=auto(); DOWNLOAD=auto(); VERIFY=auto()
    INSTALL=auto(); REPORT=auto(); ROLLBACK=auto(); DONE=auto(); ERROR=auto()

@dataclass
class UpdateRequest:
    version: str
    meta_url: str
    image_url: str
    expected_sha256: str
    extra: Dict[str, Any] | None = None

@dataclass
class Ctx:
    req: UpdateRequest
    meta_local: Optional[str]=None
    image_local: Optional[str]=None
    started_at: float=time.time()
    err: Optional[str]=None

class Updater:
    def __init__(self, storage: Storage, transport: Transport,
                 verifier: Verifier, installer: Installer, reporter):
        self.storage=storage; self.transport=transport
        self.verifier=verifier; self.installer=installer; self.reporter=reporter
        self.state=State.IDLE; self.ctx: Optional[Ctx]=None

    def run(self, req: UpdateRequest):
        self.ctx=Ctx(req=req)
        try:
            self._go(State.FETCH_META)
            self._go(State.DOWNLOAD)
            self._go(State.VERIFY)
            self._go(State.INSTALL)
            self._go(State.REPORT)
            self._set(State.DONE)
        except Exception as e:
            self.ctx.err=str(e)
            if self.state in (State.INSTALL, State.REPORT):
                try: self._go(State.ROLLBACK)
                except Exception as re: self.ctx.err+=f" | rollback_err={re}"
            self._set(State.ERROR)
        finally:
            self.storage.save_state({"state": self.state.name, "ctx": self._snapshot()})

    def _go(self, s: State):
        self._set(s)
        if s==State.FETCH_META:
            self.ctx.meta_local=self.transport.fetch(self.ctx.req.meta_url,
                                                     self.storage.meta_path(self.ctx.req.version))
        elif s==State.DOWNLOAD:
            self.ctx.image_local=self.transport.fetch(self.ctx.req.image_url,
                                                      self.storage.image_path(self.ctx.req.version))
            self.verifier.quick_hash_check(self.ctx.image_local, self.ctx.req.expected_sha256)
        elif s==State.VERIFY:
            vr: VerifyResult=self.verifier.verify_with_meta(self.ctx.meta_local, self.ctx.image_local)
            if not vr.ok: raise RuntimeError(f"verify failed: {vr.reason}")
        elif s==State.INSTALL:
            ir: InstallResult=self.installer.install(self.ctx.image_local, self.ctx.req.version)
            if not ir.ok: raise RuntimeError(f"install failed: {ir.reason}")
        elif s==State.REPORT:
            self.reporter.report("success", {"version": self.ctx.req.version})
        elif s==State.ROLLBACK:
            self.installer.rollback()
            self.reporter.report("rollback", {"version": self.ctx.req.version})

    def _set(self, s: State):
        self.state=s
        self.storage.save_state({"state": self.state.name, "ctx": self._snapshot()})

    def _snapshot(self):
        return {"version": self.ctx.req.version, "meta_local": self.ctx.meta_local,
                "image_local": self.ctx.image_local, "err": self.ctx.err,
                "started_at": self.ctx.started_at}
