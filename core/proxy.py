"""
Vers Suite - Core Proxy Module
Handles MITM proxy via mitmproxy with real-time intercept support.
Author: Xnuvers007 | Vers Suite
"""

import asyncio
import threading
import queue
import logging
import time
from typing import Dict, Any, Optional

logger = logging.getLogger("VersProxy")


def _safe_log(level: int, message: str) -> None:
    """Log without relying on mitmproxy's event-loop-backed handlers."""
    safe_logger = logging.getLogger("VersProxySafe")
    if not safe_logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(levelname)s:%(name)s:%(message)s")
        handler.setFormatter(formatter)
        safe_logger.addHandler(handler)
        safe_logger.setLevel(logging.INFO)
        safe_logger.propagate = False
    try:
        safe_logger.log(level, message)
    except Exception:
        # As a last resort, avoid raising during shutdown.
        pass


# ─────────────────────────────────────────────
# mitmproxy Addon
# ─────────────────────────────────────────────
class VersAddon:
    """
    mitmproxy addon that bridges proxy events to the PyQt5 UI.
    Uses asyncio.Event per flow for non-blocking intercept.
    Supports scope filtering, response interception, match/replace, and WebSocket.
    """

    def __init__(
        self,
        event_queue: queue.Queue,
        intercept_enabled: threading.Event,
        response_intercept_enabled: threading.Event,
        loop_ref: list,           # [asyncio.AbstractEventLoop]
        action_store: dict,       # flow_id -> {action, modifications, async_event}
        resp_action_store: dict,  # flow_id -> {action, modifications, async_event}
        scope_manager=None,
        match_replace_engine=None,
    ):
        self.event_queue = event_queue
        self.intercept_enabled = intercept_enabled
        self.response_intercept_enabled = response_intercept_enabled
        self.loop_ref = loop_ref
        self.action_store = action_store
        self.resp_action_store = resp_action_store
        self.scope_manager = scope_manager
        self.match_replace_engine = match_replace_engine
        self._flow_index: Dict[str, Any] = {}

    # ── helpers ──────────────────────────────
    def _flow_to_dict(self, flow) -> dict:
        req = flow.request
        return {
            "flow_id":      flow.id,
            "method":       req.method,
            "url":          req.pretty_url,
            "host":         req.pretty_host,
            "port":         req.port,
            "scheme":       req.scheme,
            "path":         req.path,
            "http_version": req.http_version,
            "headers":      dict(req.headers),
            "body":         req.content.decode("utf-8", errors="replace"),
            "timestamp":    time.strftime("%H:%M:%S"),
        }

    def _response_to_dict(self, flow) -> dict:
        resp = flow.response
        try:
            elapsed = (resp.timestamp_end - flow.request.timestamp_start) * 1000
        except Exception:
            elapsed = 0
        return {
            "flow_id":      flow.id,
            "status_code":  resp.status_code,
            "reason":       resp.reason,
            "headers":      dict(resp.headers),
            "body":         resp.content.decode("utf-8", errors="replace"),
            "elapsed_ms":   round(elapsed, 1),
            "length":       len(resp.content),
        }

    # ── mitmproxy hooks ───────────────────────
    async def request(self, flow):
        from mitmproxy import http as mhttp
        self._flow_index[flow.id] = flow

        # Scope check
        in_scope = True
        if self.scope_manager:
            in_scope = self.scope_manager.is_in_scope(flow.request.pretty_url)

        # Apply match & replace rules to request
        if self.match_replace_engine and self.match_replace_engine.enabled:
            headers = dict(flow.request.headers)
            body = flow.request.content.decode("utf-8", errors="replace")
            headers, body = self.match_replace_engine.apply_request(headers, body)
            flow.request.headers.clear()
            for k, v in headers.items():
                flow.request.headers[k] = v
            flow.request.content = body.encode("utf-8")

        if self.intercept_enabled.is_set() and in_scope:
            flow.intercept()
            async_event = asyncio.Event()
            self.action_store[flow.id] = {
                "action":        "forward",
                "modifications": {},
                "async_event":   async_event,
            }

            self.event_queue.put({
                "type": "intercept",
                "in_scope": in_scope,
                **self._flow_to_dict(flow),
            })

            # Non-blocking wait — other requests still process
            await async_event.wait()

            entry = self.action_store.pop(flow.id, {})
            action = entry.get("action", "forward")
            mods   = entry.get("modifications", {})

            if action == "drop":
                flow.kill()
                return

            # Apply edits
            if mods:
                if "method"  in mods: flow.request.method  = mods["method"]
                if "path"    in mods: flow.request.path    = mods["path"]
                if "body"    in mods: flow.request.content = mods["body"].encode("utf-8")
                if "headers" in mods:
                    flow.request.headers.clear()
                    for k, v in mods["headers"].items():
                        flow.request.headers[k] = v

            flow.resume()
        else:
            self.event_queue.put({
                "type": "history",
                "in_scope": in_scope,
                **self._flow_to_dict(flow),
            })

    async def response(self, flow):
        # Apply match & replace rules to response
        if self.match_replace_engine and self.match_replace_engine.enabled:
            headers = dict(flow.response.headers)
            body = flow.response.content.decode("utf-8", errors="replace")
            headers, body = self.match_replace_engine.apply_response(headers, body)
            flow.response.headers.clear()
            for k, v in headers.items():
                flow.response.headers[k] = v
            flow.response.content = body.encode("utf-8")

        # Response interception
        in_scope = True
        if self.scope_manager:
            in_scope = self.scope_manager.is_in_scope(flow.request.pretty_url)

        if self.response_intercept_enabled.is_set() and in_scope:
            flow.intercept()
            async_event = asyncio.Event()
            self.resp_action_store[flow.id] = {
                "action":        "forward",
                "modifications": {},
                "async_event":   async_event,
            }

            self.event_queue.put({
                "type": "response_intercept",
                "flow_id": flow.id,
                **self._response_to_dict(flow),
            })

            await async_event.wait()

            entry = self.resp_action_store.pop(flow.id, {})
            action = entry.get("action", "forward")
            mods   = entry.get("modifications", {})

            if action == "drop":
                flow.kill()
                return

            if mods:
                if "body" in mods:
                    flow.response.content = mods["body"].encode("utf-8")
                if "headers" in mods:
                    flow.response.headers.clear()
                    for k, v in mods["headers"].items():
                        flow.response.headers[k] = v
                if "status_code" in mods:
                    flow.response.status_code = mods["status_code"]

            flow.resume()
        else:
            self.event_queue.put({
                "type": "response",
                **self._response_to_dict(flow),
            })

    async def error(self, flow):
        self.event_queue.put({
            "type":    "error",
            "flow_id": flow.id,
            "message": str(flow.error),
        })

    def websocket_message(self, flow):
        """Capture WebSocket messages (if supported by mitmproxy version)."""
        try:
            msg = flow.websocket.messages[-1]
            self.event_queue.put({
                "type": "websocket",
                "flow_id": flow.id,
                "url": flow.request.pretty_url,
                "host": flow.request.pretty_host,
                "direction": "outgoing" if msg.from_client else "incoming",
                "content": msg.text if hasattr(msg, 'text') else msg.content.decode('utf-8', 'replace'),
                "is_text": msg.is_text if hasattr(msg, 'is_text') else True,
                "length": len(msg.content) if hasattr(msg, 'content') else 0,
                "timestamp": time.strftime("%H:%M:%S"),
            })
        except Exception:
            pass


# ─────────────────────────────────────────────
# Proxy Server
# ─────────────────────────────────────────────
class ProxyServer:
    """
    Manages mitmproxy lifecycle in a daemon thread.
    Thread-safe interface for the UI layer.
    """

    def __init__(self):
        self.event_queue    = queue.Queue()
        self.intercept_enabled = threading.Event()
        self.response_intercept_enabled = threading.Event()
        self.action_store   = {}   # flow_id -> action dict
        self.resp_action_store = {}   # flow_id -> response action dict
        self._loop_ref      = [None]   # holds the asyncio loop
        self._master        = None
        self._thread        = None
        self.running        = False
        self.host           = "127.0.0.1"
        self.port           = 8080
        self.scope_manager  = None
        self.match_replace_engine = None

    # ── lifecycle ─────────────────────────────
    def start(self, host: str = "127.0.0.1", port: int = 8080):
        self.host    = host
        self.port    = port
        self.running = True
        self._thread = threading.Thread(
            target=self._thread_main, args=(host, port), daemon=True
        )
        self._thread.start()
        logger.info(f"Proxy started on {host}:{port}")

    def stop(self):
        self.running = False
        loop = self._loop_ref[0]
        master = self._master
        if master and loop:
            if loop.is_closed():
                _safe_log(logging.WARNING, "Proxy loop already closed; skip shutdown")
            else:
                try:
                    loop.call_soon_threadsafe(master.shutdown)
                except Exception as e:
                    _safe_log(logging.ERROR, f"Error stopping proxy: {e}")
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=2)
            except Exception as e:
                _safe_log(logging.WARNING, f"Error joining proxy thread: {e}")
        logger.info("Proxy stopped")

    def _thread_main(self, host: str, port: int):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop_ref[0] = loop
        try:
            loop.run_until_complete(self._run_proxy(host, port))
        except Exception as e:
            logger.error(f"Proxy thread error: {e}")
            self.event_queue.put({"type": "proxy_error", "message": str(e)})
        finally:
            try:
                if not loop.is_closed():
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    if pending:
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                    try:
                        loop.run_until_complete(loop.shutdown_asyncgens())
                    except Exception:
                        pass
            except Exception as e:
                _safe_log(logging.WARNING, f"Error while draining loop: {e}")
            loop.close()
            self._loop_ref[0] = None
            self._master = None

    async def _run_proxy(self, host: str, port: int):
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        opts = options.Options(
            listen_host=host,
            listen_port=port,
            ssl_insecure=True,
        )
        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        addon = VersAddon(
            self.event_queue,
            self.intercept_enabled,
            self.response_intercept_enabled,
            self._loop_ref,
            self.action_store,
            self.resp_action_store,
            self.scope_manager,
            self.match_replace_engine,
        )
        self._master.addons.add(addon)
        self.event_queue.put({"type": "proxy_started", "host": host, "port": port})
        await self._master.run()

    # ── intercept actions ─────────────────────
    def forward_flow(self, flow_id: str, modifications: dict = None):
        loop = self._loop_ref[0]
        if loop and flow_id in self.action_store:
            entry = self.action_store[flow_id]
            entry["action"] = "forward"
            entry["modifications"] = modifications or {}
            self._set_event_threadsafe(loop, flow_id)

    def drop_flow(self, flow_id: str):
        loop = self._loop_ref[0]
        if loop and flow_id in self.action_store:
            self.action_store[flow_id]["action"] = "drop"
            self._set_event_threadsafe(loop, flow_id)

    def flush_intercepts(self):
        """Auto-forward any pending intercepted requests."""
        loop = self._loop_ref[0]
        if not loop or loop.is_closed():
            return
        for flow_id, entry in list(self.action_store.items()):
            entry["action"] = "forward"
            entry["modifications"] = {}
            self._set_event_threadsafe(loop, flow_id)

    def drop_all_intercepts(self):
        """Drop any pending intercepted requests."""
        loop = self._loop_ref[0]
        if not loop or loop.is_closed():
            return
        for flow_id, entry in list(self.action_store.items()):
            entry["action"] = "drop"
            entry["modifications"] = {}
            self._set_event_threadsafe(loop, flow_id)

    def _set_event_threadsafe(self, loop: asyncio.AbstractEventLoop, flow_id: str):
        entry = self.action_store.get(flow_id)
        if not entry:
            return
        async_event = entry.get("async_event")
        if not async_event:
            return
        try:
            loop.call_soon_threadsafe(async_event.set)
        except Exception as e:
            _safe_log(logging.WARNING, f"Error releasing flow {flow_id}: {e}")

    # ── response intercept actions ─────────────
    def forward_response(self, flow_id: str, modifications: dict = None):
        loop = self._loop_ref[0]
        if loop and flow_id in self.resp_action_store:
            entry = self.resp_action_store[flow_id]
            entry["action"] = "forward"
            entry["modifications"] = modifications or {}
            self._set_resp_event_threadsafe(loop, flow_id)

    def drop_response(self, flow_id: str):
        loop = self._loop_ref[0]
        if loop and flow_id in self.resp_action_store:
            self.resp_action_store[flow_id]["action"] = "drop"
            self._set_resp_event_threadsafe(loop, flow_id)

    def flush_response_intercepts(self):
        loop = self._loop_ref[0]
        if not loop or loop.is_closed():
            return
        for flow_id, entry in list(self.resp_action_store.items()):
            entry["action"] = "forward"
            entry["modifications"] = {}
            self._set_resp_event_threadsafe(loop, flow_id)

    def _set_resp_event_threadsafe(self, loop, flow_id):
        entry = self.resp_action_store.get(flow_id)
        if not entry:
            return
        async_event = entry.get("async_event")
        if not async_event:
            return
        try:
            loop.call_soon_threadsafe(async_event.set)
        except Exception as e:
            _safe_log(logging.WARNING, f"Error releasing response {flow_id}: {e}")

    # ── state helpers ─────────────────────────
    def enable_intercept(self):  self.intercept_enabled.set()
    def disable_intercept(self): self.intercept_enabled.clear()
    def is_intercepting(self) -> bool: return self.intercept_enabled.is_set()

    def enable_response_intercept(self):  self.response_intercept_enabled.set()
    def disable_response_intercept(self): self.response_intercept_enabled.clear()
    def is_response_intercepting(self) -> bool: return self.response_intercept_enabled.is_set()

    def get_cert_path(self) -> Optional[str]:
        import os
        candidates = [
            os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem"),
            os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.cer"),
        ]
        for p in candidates:
            if os.path.exists(p):
                return p
        return None

    def get_cert_dir(self) -> str:
        import os
        return os.path.expanduser("~/.mitmproxy")