"""Concrete bounded HTTPS broker host. Import never creates a listener.

SocketBody owns the socket; cancellation interrupts actual recv calls. Every
connection carries one request and is closed, including rejected/partial bodies.
"""

import argparse, importlib, queue, re, select, socket, ssl, threading, time
from runner_diagnostics import log_failure


class ExecuteContext:
    """Host-owned job operation deadline and cancellation, one monitor per worker.

    Created only by BrokerController after authentication, complete JSON, grant,
    and execute plan/nonce or one-use artifact checks. Bounds compute or artifact
    transfer within the same job lease. The body upload deadline is unchanged.
    """

    def __init__(self, body, expires_at, cancel_backend):
        started = time.monotonic()
        remaining = (expires_at - time.time() * 1000) / 1000
        if not callable(cancel_backend) or remaining <= 0 or time.monotonic() >= body.deadline:
            raise ValueError("EXECUTE_ADMISSION_EXPIRED")
        self.body = body
        self.deadline = started + min(remaining, body.execute_timeout, 900)
        self.cancel_backend = cancel_backend
        self.cancelled = threading.Event()
        self.stop = threading.Event()
        self.lock = threading.RLock()
        self.io_lock = threading.Lock()
        self.cleanup_lock = threading.Lock()
        self.cleanup_error = None
        self.cleanup_confirmed = False
        self.finished = False
        self.monitor = threading.Thread(target=self._monitor, name="isign-execute-monitor")
        self.monitor.start()

    def cancel(self):
        with self.lock:
            if self.finished:
                return
            self.cancelled.set()
        try:
            socket.socket.shutdown(self.body.connection, socket.SHUT_RDWR)
        except OSError:
            pass

    def check(self):
        if (
            self.cancelled.is_set()
            or self.body.host_stop.is_set()
            or time.monotonic() >= self.deadline
        ):
            self.cancel()
            raise ValueError("EXECUTE_CANCELLED")

    def commit(self, publish):
        # Publication and the cancellation flag share a lock. Destruction also
        # removes any result published just before cancellation won the race.
        with self.lock:
            self.check()
            return publish()

    def _cleanup(self):
        # A synchronous failure and the cancellation monitor may race. Confirm
        # physical destruction once, and retain an unconfirmed cleanup failure.
        with self.cleanup_lock:
            if self.cleanup_confirmed:
                return
            if self.cleanup_error is not None:
                raise self.cleanup_error
            try:
                if self.cancel_backend() is not True:
                    raise ValueError("EXECUTE_DESTRUCTION_UNCONFIRMED")
                self.cleanup_confirmed = True
            except BaseException as exc:
                self.cleanup_error = exc
                raise

    def fail(self):
        # Compute already returned an error. Retire the guest before replying,
        # without treating the completed computation as a socket cancellation.
        # The monitor and the original deadline remain active through the send.
        self.check()
        try:
            self._cleanup()
        except BaseException as exc:
            self.cancel()
            raise ValueError("EXECUTE_DESTRUCTION_UNCONFIRMED") from exc
        self.check()

    def _monitor(self):
        try:
            while not self.stop.is_set() and not self.cancelled.is_set():
                if self.body.host_stop.is_set() or time.monotonic() >= self.deadline:
                    self.cancel()
                    break
                with self.io_lock:
                    readable = select.select([self.body.connection], [], [], 0)[0]
                    if readable:
                        self.body.connection.settimeout(0.01)
                        try:
                            # No further request bytes are legal on this single
                            # request connection; EOF and pipelining both abort.
                            self.body.connection.recv(1)
                            self.cancel()
                            break
                        except (socket.timeout, ssl.SSLWantReadError):
                            pass
                self.stop.wait(min(0.05, max(0, self.deadline - time.monotonic())))
        except (OSError, ValueError):
            self.cancel()
        finally:
            if self.cancelled.is_set():
                try:
                    self._cleanup()
                except BaseException as exc:
                    self.cleanup_error = exc

    def finish(self, success):
        with self.lock:
            if self.finished:
                return
            if (
                (not success and not self.cleanup_confirmed)
                or self.cancelled.is_set()
                or self.body.host_stop.is_set()
                or time.monotonic() >= self.deadline
            ):
                self.cancel()
            else:
                self.finished = True
            self.stop.set()
        self.monitor.join(self.body.cleanup_timeout)
        if self.monitor.is_alive():
            raise ValueError("EXECUTE_MONITOR_CLEANUP_UNCONFIRMED")
        if self.cleanup_error is not None:
            raise ValueError("EXECUTE_DESTRUCTION_UNCONFIRMED") from self.cleanup_error
        with self.lock:
            self.finished = True


class SocketBody:
    def __init__(
        self,
        connection,
        headers,
        buffered=b"",
        *,
        deadline,
        limit,
        host_stop=None,
        execute_timeout=900,
        cleanup_timeout=125,
    ):
        self.connection = connection
        self.buffer = buffered
        self.deadline = deadline
        self.limit = limit
        self.total = 0
        self.done = False
        self.chunk_remaining = 0
        self.host_stop = host_stop or threading.Event()
        self.execute_timeout = execute_timeout
        self.cleanup_timeout = cleanup_timeout
        self.execution = None
        length = headers.get("content-length")
        transfer = headers.get("transfer-encoding")
        if length is not None and transfer is not None:
            raise ValueError("AMBIGUOUS_BODY_FRAMING")
        if transfer is not None and transfer != "chunked":
            raise ValueError("TRANSFER_ENCODING_REJECTED")
        if length is None and transfer is None:
            raise ValueError("BODY_LENGTH_REQUIRED")
        if length is not None and not re.fullmatch(r"0|[1-9][0-9]{0,9}", length):
            raise ValueError("BODY_LENGTH_INVALID")
        self.remaining = int(length) if length is not None else None
        if self.remaining is not None and self.remaining > limit:
            raise ValueError("BODY_LIMIT")

    def authorize_execute(self, expires_at, cancel_backend):
        if self.execution is not None or not self.done or self.buffer:
            raise ValueError("EXECUTE_COMPLETE_BODY_REQUIRED")
        self.execution = ExecuteContext(self, expires_at, cancel_backend)
        return self.execution

    def cancel(self):
        if self.execution is not None:
            self.execution.cancel()
        self.done = True
        self.buffer = b""
        try:
            socket.socket.shutdown(self.connection, socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()

    def _receive(self):
        while True:
            if self.done:
                raise ValueError("BODY_CANCELLED")
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise ValueError("BODY_READ_TIMEOUT")
            # Some SSL/select implementations do not wake promptly on a close
            # from another thread. Poll actual bounded recv with the same deadline.
            self.connection.settimeout(min(0.1, left))
            try:
                block = self.connection.recv(65536)
                break
            except socket.timeout:
                continue
        if not block:
            raise ValueError("BODY_DISCONNECTED")
        self.buffer += block

    def _exact(self, size):
        while len(self.buffer) < size:
            self._receive()
        block = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return block

    def _line(self):
        while b"\r\n" not in self.buffer:
            if len(self.buffer) > 128:
                raise ValueError("CHUNK_LINE_LIMIT")
            self._receive()
        line, self.buffer = self.buffer.split(b"\r\n", 1)
        if len(line) > 128:
            raise ValueError("CHUNK_LINE_LIMIT")
        return line

    def read(self, size=65536):
        if not 0 < size <= 65536:
            raise ValueError("BOUNDED_BODY_READ_REQUIRED")
        if self.done:
            return b""
        if self.remaining is not None:
            if self.remaining == 0:
                self.done = True
                return b""
            size = min(size, self.remaining)
        else:
            if not self.chunk_remaining:
                line = self._line()
                if not re.fullmatch(rb"[0-9a-fA-F]{1,9}", line):
                    raise ValueError("CHUNK_FRAMING_REJECTED")
                self.chunk_remaining = int(line, 16)
                if self.total + self.chunk_remaining > self.limit:
                    raise ValueError("BODY_LIMIT")
                if not self.chunk_remaining:
                    if self._line() != b"":
                        raise ValueError("TRAILERS_REJECTED")
                    self.done = True
                    return b""
            size = min(size, self.chunk_remaining)
        if not self.buffer:
            self._receive()
        block = self.buffer[:size]
        self.buffer = self.buffer[len(block) :]
        self.total += len(block)
        if self.total > self.limit:
            raise ValueError("BODY_LIMIT")
        if self.remaining is not None:
            self.remaining -= len(block)
        else:
            self.chunk_remaining -= len(block)
            if not self.chunk_remaining and self._exact(2) != b"\r\n":
                raise ValueError("CHUNK_FRAMING_REJECTED")
        return block

    def __iter__(self):
        return self

    def __next__(self):
        block = self.read()
        if not block:
            raise StopIteration
        return block


class HTTPSBrokerHost:
    def __init__(
        self,
        broker,
        context,
        *,
        workers=4,
        request_timeout=120,
        execute_timeout=900,
        cleanup_timeout=125,
    ):
        if (
            not isinstance(context, ssl.SSLContext)
            or context.protocol != ssl.PROTOCOL_TLS_SERVER
            or not 1 <= workers <= 16
            or not 0 < request_timeout <= 120
            or not 0 < execute_timeout <= 900
            or not 0 < cleanup_timeout <= 125
        ):
            raise ValueError("HTTPS_HOST_CONFIGURATION_REQUIRED")
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.broker = broker
        self.context = context
        self.workers = workers
        self.timeout = request_timeout
        self.pending = queue.Queue(workers)
        self.stop = threading.Event()
        self.active = set()
        self.lock = threading.Lock()
        self.threads = []
        self.listener = None
        self.bodies = set()
        self.failures = []
        self.execute_timeout = execute_timeout
        self.cleanup_timeout = cleanup_timeout

    def handle(self, connection, *, tls=True, deadline=None):
        body = None
        response = None
        success = False
        stage, method, path = "read-request", None, None
        deadline = deadline or time.monotonic() + self.timeout
        try:
            if not tls:
                raise ValueError("TLS_REQUIRED")
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            raw = b""
            while b"\r\n\r\n" not in raw:
                if self.stop.is_set():
                    raise ValueError("HOST_STOPPED")
                if len(raw) > 16384:
                    raise ValueError("HEADER_LIMIT")
                left = deadline - time.monotonic()
                if left <= 0:
                    raise ValueError("HEADER_TIMEOUT")
                connection.settimeout(min(0.1, left))
                try:
                    block = connection.recv(4096)
                except socket.timeout:
                    continue
                if not block:
                    raise ValueError("HEADER_DISCONNECTED")
                raw += block
            header, buffer = raw.split(b"\r\n\r\n", 1)
            if len(header) > 16384:
                raise ValueError("HEADER_LIMIT")
            lines = header.decode("ascii").split("\r\n")
            request = lines.pop(0).split(" ")
            if len(request) != 3 or request[2] != "HTTP/1.1":
                raise ValueError("HTTP_VERSION_REQUIRED")
            method, path, _ = request
            headers = {}
            for line in lines:
                name, separator, value = line.partition(":")
                name = name.lower()
                if (
                    not separator
                    or not re.fullmatch(r"[a-z0-9-]+", name)
                    or name in headers
                    or any(ord(c) < 32 or ord(c) == 127 for c in value)
                ):
                    raise ValueError("HEADER_INVALID")
                headers[name] = value.strip()
            if "host" not in headers or headers.get("expect"):
                raise ValueError("HOST_OR_EXPECT_REJECTED")
            limit = (1 << 30) if path.endswith("/source") else (8 << 20)
            stage = "read-body"
            body = SocketBody(
                connection,
                headers,
                buffer,
                deadline=deadline,
                limit=limit,
                host_stop=self.stop,
                execute_timeout=self.execute_timeout,
                cleanup_timeout=self.cleanup_timeout,
            )
            with self.lock:
                self.bodies.add(body)
            stage = "dispatch"
            response = self.broker.dispatch(method, path, headers, body, tls=True)
            # Compute and response transmission consume the SAME deadline.
            execution = body.execution
            if execution is not None:
                deadline = execution.deadline

            def send(data):
                left = deadline - time.monotonic()
                if left <= 0 or self.stop.is_set():
                    raise ValueError("RESPONSE_TIMEOUT")
                if execution is not None:
                    with execution.io_lock:
                        execution.check()
                        connection.settimeout(deadline - time.monotonic())
                        connection.sendall(data)
                else:
                    connection.settimeout(left)
                    connection.sendall(data)

            stage = "send-response"
            status = response.status
            response_headers = {**response.headers, "connection": "close"}
            wire = (
                "HTTP/1.1 "
                + str(status)
                + " Response\r\n"
                + "".join(k + ": " + v + "\r\n" for k, v in response_headers.items())
                + "\r\n"
            )
            send(wire.encode("ascii"))
            for chunk in response.body:
                send(chunk)
            success = status < 400
        except (OSError, ValueError) as exc:
            log_failure(
                "runner_http_failed",
                exc,
                stage=stage,
                method=method,
                path=path,
                bytesReceived=body.total if body is not None else 0,
            )
            # Expired/disconnected requests close without an extra send budget.
            if body is None and not self.stop.is_set() and time.monotonic() < deadline:
                try:
                    connection.settimeout(deadline - time.monotonic())
                    connection.sendall(
                        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    )
                except OSError:
                    pass
        finally:
            try:
                if response is not None and callable(getattr(response.body, "close", None)):
                    response.body.close()
            finally:
                if body is not None:
                    try:
                        if body.execution is not None:
                            body.execution.finish(success)
                    except ValueError as exc:
                        log_failure("runner_http_cleanup_failed", exc, method=method, path=path)
                        with self.lock:
                            self.failures.append(exc)
                        self.stop.set()
                    finally:
                        body.cancel()
                        if body.execution is None or not body.execution.monitor.is_alive():
                            with self.lock:
                                self.bodies.discard(body)
                else:
                    try:
                        socket.socket.shutdown(connection, socket.SHUT_RDWR)
                    except OSError:
                        pass
                    connection.close()

    def _worker(self):
        while not self.stop.is_set():
            try:
                raw = self.pending.get(timeout=0.1)
            except queue.Empty:
                continue
            connection = raw
            deadline = time.monotonic() + self.timeout
            with self.lock:
                self.active.add(raw)
            try:
                raw.settimeout(self.timeout)
                connection = self.context.wrap_socket(
                    raw, server_side=True, do_handshake_on_connect=False
                )
                with self.lock:
                    self.active.discard(raw)
                    self.active.add(connection)
                connection.setblocking(False)
                while True:
                    if self.stop.is_set() or time.monotonic() >= deadline:
                        raise ValueError("TLS_HANDSHAKE_CANCELLED")
                    try:
                        connection.do_handshake()
                        break
                    except ssl.SSLWantReadError:
                        select.select(
                            [connection], [], [], min(0.05, max(0, deadline - time.monotonic()))
                        )
                    except ssl.SSLWantWriteError:
                        select.select(
                            [], [connection], [], min(0.05, max(0, deadline - time.monotonic()))
                        )
                self.handle(connection, deadline=deadline)
            except (OSError, ValueError):
                connection.close()
            finally:
                connection.close()
                with self.lock:
                    self.active.discard(raw)
                    self.active.discard(connection)
                self.pending.task_done()

    def serve(self, address):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(address)
        self.listener.listen(self.workers)
        self.listener.settimeout(0.2)
        self.threads = [
            threading.Thread(target=self._worker, name="isign-https-worker-" + str(i))
            for i in range(self.workers)
        ]
        for worker in self.threads:
            worker.start()
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop.is_set():
                        break
                    raise
                try:
                    self.pending.put_nowait(connection)
                except queue.Full:
                    connection.close()
        finally:
            self.close()

    def close(self):
        self.stop.set()
        if self.listener:
            self.listener.close()
        with self.lock:
            connections = list(self.active)
            bodies = list(self.bodies)
        for body in bodies:
            body.cancel()
        pending = []
        while True:
            try:
                pending.append(self.pending.get_nowait())
                self.pending.task_done()
            except queue.Empty:
                break
        for connection in connections:
            try:
                socket.socket.shutdown(connection, socket.SHUT_RDWR)
            except OSError:
                pass
        for connection in pending:
            connection.close()
        deadline = time.monotonic() + self.cleanup_timeout
        for worker in self.threads:
            if worker is not threading.current_thread():
                worker.join(max(0, deadline - time.monotonic()))
        with self.lock:
            alive = any(
                worker.is_alive()
                for worker in self.threads
                if worker is not threading.current_thread()
            ) or any(
                body.execution is not None and body.execution.monitor.is_alive()
                for body in self.bodies
            )
            if alive or self.failures:
                raise ValueError("HTTPS_HOST_CLEANUP_UNCONFIRMED")
        return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--factory",
        required=True,
        help="trusted module:function returning a recovered BrokerController",
    )
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    module, function = args.factory.split(":")
    broker = getattr(importlib.import_module(module), function)()
    if not broker.recovery_ready:
        raise ValueError("BROKER_RECOVERY_REQUIRED")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.certificate, args.private_key)
    host = HTTPSBrokerHost(broker, context)
    try:
        host.serve((args.host, args.port))
    except KeyboardInterrupt:
        host.close()


if __name__ == "__main__":
    main()
