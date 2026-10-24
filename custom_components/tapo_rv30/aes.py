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

from .tpap import AuthError, TapoVacuumClient, _resend_safe

_LOGGER = logging.getLogger(__name__)


class _LoopThread:
    """One private asyncio loop per client, so the blocking API the
    coordinator and entities use (via the executor) can drive python-kasa."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._closed = False

    def run(self, coro, timeout: float = 60):
        if self._closed:
            coro.close()
            raise RuntimeError("client is closed")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            future.cancel()     # do not let a call the caller gave up on land later
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        if not self._thread.is_alive():
            self._loop.close()


class AesVacuumClient(TapoVacuumClient):
    """Same blocking method surface as TapoVacuumClient, AES transport underneath."""

    def __init__(self, host: str, username: str, password: str, port: int = 4433,
                 cache_dir=None) -> None:
        super().__init__(host, username, password, port, cache_dir)
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

    async def _drop(self) -> None:
        """Forget the python-kasa device and close its network session."""
        dev, self._device = self._device, None
        if dev is not None:
            try:
                await dev.disconnect()
            except Exception as exc:
                _LOGGER.debug("Disconnect failed: %s", exc)

    def close(self) -> None:
        try:
            self._loopthread.run(self._drop(), timeout=10)
        except Exception:
            pass
        self._loopthread.close()

    # ---- send ----------------------------------------------------------------
    async def _query(self, method: str, params: dict | None) -> dict:
        from kasa.exceptions import AuthenticationError, DeviceError, _RetryableError

        dev = await self._connect()
        request = {method: params or {}}
        # python-kasa retries timeouts and dropped connections itself. That is fine for a
        # read, but a write whose reply was lost may already have been carried out, so a
        # write is sent once and only repeated when the robot answered that it refused it.
        safe = _resend_safe(method, params)
        try:
            try:
                resp = await dev.protocol.query(request, retry_count=3 if safe else 0)
            except AuthenticationError as exc:
                await self._drop()
                raise AuthError(str(exc)) from exc
            except _RetryableError as exc:
                # The robot answered and refused (expired session and the like): not run.
                _LOGGER.debug("%s refused (%s), reconnecting", method, exc)
                await self._drop()
                dev = await self._connect()
                resp = await dev.protocol.query(request, retry_count=3 if safe else 0)
            except DeviceError:
                raise
            except Exception as exc:
                await self._drop()
                if not safe:
                    raise RuntimeError(f"no reply to {method}; not sent again in case the robot "
                                       "already acted on it, check its state") from exc
                # Reboot or transient network: reconnect once for a read.
                _LOGGER.debug("%s failed (%s), reconnecting", method, exc)
                dev = await self._connect()
                resp = await dev.protocol.query(request)
        except AuthenticationError as exc:
            raise AuthError(str(exc)) from exc
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
        # A getter the robot does not support comes back as a SmartErrorCode in its slot,
        # not as an exception: leave it out, like the TPAP batch does.
        return {m: resp[m] for m, _ in requests if isinstance(resp.get(m), dict)}

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
