"""AES-transport client for Tapo RV vacuums.

Some units (RV30C, RV30C Mop, some RV20/RV30 firmware) report
``encrypt_type: AES`` during discovery instead of TPAP/SPAKE2+. python-kasa,
which Home Assistant already ships for its core tplink integration, speaks
that scheme, so this client lets python-kasa do the login and transport and
inherits every vacuum command from TapoVacuumClient unchanged: the device
methods and payloads are the same, only the wrapping differs.

Based on the AES client in github.com/peggleg/tapo-rv30 (thanks @peggleg).
"""
from __future__ import annotations

import asyncio
import logging
import threading

from .tpap import AuthError, TapoVacuumClient

_LOGGER = logging.getLogger(__name__)


class _LoopThread:
    """One private asyncio loop per client, so the blocking API the
    coordinator and entities use (via the executor) can drive python-kasa."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def run(self, coro, timeout: float = 60):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=timeout)

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)


class AesVacuumClient(TapoVacuumClient):
    """Same blocking method surface as TapoVacuumClient, AES transport underneath."""

    def __init__(self, host: str, username: str, password: str, port: int = 4433) -> None:
        super().__init__(host, username, password, port)
        self._loopthread = _LoopThread()
        self._device = None

    # ---- connection ----------------------------------------------------------
    async def _connect(self):
        if self._device is not None:
            return self._device
        # Imported here so a TPAP-only install never needs python-kasa at import time.
        from kasa import Discover
        from kasa.exceptions import AuthenticationError

        try:
            dev = await Discover.discover_single(
                self.host, username=self.username, password=self.password
            )
            await dev.update()
        except AuthenticationError as exc:
            raise AuthError(str(exc)) from exc
        self._device = dev
        _LOGGER.debug("AES session established with %s (%s)", self.host, dev.model)
        return dev

    def authenticate(self) -> None:
        self._loopthread.run(self._connect())

    def _ensure_auth(self) -> None:
        self.authenticate()

    def close(self) -> None:
        self._loopthread.close()

    # ---- send ----------------------------------------------------------------
    async def _query(self, method: str, params: dict | None) -> dict:
        from kasa.exceptions import AuthenticationError, DeviceError

        dev = await self._connect()
        request = {method: params or {}}
        try:
            try:
                resp = await dev.protocol.query(request)
            except AuthenticationError as exc:
                self._device = None
                raise AuthError(str(exc)) from exc
            except DeviceError:
                raise
            except Exception as exc:
                # Expired session, reboot, transient network: reconnect once.
                _LOGGER.debug("%s failed (%s), reconnecting", method, exc)
                self._device = None
                dev = await self._connect()
                resp = await dev.protocol.query(request)
        except DeviceError as exc:
            code = getattr(exc, "error_code", None)
            code = getattr(code, "value", code)
            raise RuntimeError(f"Device error {code if code is not None else exc}") from exc
        return {"error_code": 0, "result": resp.get(method)}

    def send(self, method: str, params: dict | None = None) -> dict:
        """Same return shape as the TPAP client: {"error_code": 0, "result": ...}."""
        with self._lock:
            return self._loopthread.run(self._query(method, params))

    async def _query_many(self, requests: list[tuple[str, dict | None]]) -> dict[str, dict]:
        dev = await self._connect()
        resp = await dev.protocol.query({m: (p or {}) for m, p in requests})
        return {m: (resp.get(m) or {}) for m, _ in requests if m in resp}

    def send_multi(self, requests: list[tuple[str, dict | None]]) -> dict[str, dict]:
        """python-kasa batches a multi-key query into multipleRequest itself."""
        with self._lock:
            try:
                return self._loopthread.run(self._query_many(requests))
            except Exception as exc:
                _LOGGER.debug("Batched query failed (%s); falling back to single requests", exc)
        out = {}
        for m, p in requests:
            try:
                out[m] = self.send(m, p)["result"] or {}
            except Exception as exc:
                _LOGGER.debug("%s failed: %s", m, exc)
        return out
