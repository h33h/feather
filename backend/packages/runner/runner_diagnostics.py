"""Bounded stderr diagnostics without request bodies, grants, keys or traceback locals."""

import base64, json, os, re, sys, traceback, urllib.parse


def log_failure(event, error, *, secrets=(), **context):
    try:
        sensitive = list(secrets) + [
            value
            for key, value in os.environ.items()
            if re.search(r"TOKEN|SECRET|PASSWORD|PRIVATE|PROOF_KEY|DATABASE_URL", key)
        ]
        values = []
        for value in sensitive:
            if isinstance(value, bytes):
                values.extend(
                    (
                        value.hex(),
                        base64.b64encode(value).decode(),
                        value.decode("utf8", errors="ignore"),
                    )
                )
            elif isinstance(value, str):
                values.append(value)

        def redact(value):
            for secret in sorted(set(values), key=len, reverse=True):
                if len(secret) >= 4:
                    value = value.replace(secret, "[REDACTED]")
            value = re.sub(
                r"-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----", "[REDACTED PEM]", value
            )
            value = re.sub(r"Bearer\s+[^\s,;]+", "Bearer [REDACTED]", value, flags=re.I)

            def url(match):
                parsed = urllib.parse.urlsplit(match.group())
                return parsed.scheme + "://" + (parsed.hostname or "redacted") + parsed.path

            return re.sub(r"https?://[^\s<>\"']+", url, value)[:2000]

        seen = set()

        def describe(exc, depth=0):
            if depth >= 4 or id(exc) in seen:
                return {"type": "TruncatedCause"}
            seen.add(id(exc))
            result = {"type": type(exc).__name__, "message": redact(str(exc))}
            result["frames"] = [
                {"file": frame.filename, "line": frame.lineno, "function": frame.name}
                for frame in traceback.extract_tb(exc.__traceback__)[-12:]
            ]
            if isinstance(exc, OSError):
                result["errno"] = exc.errno
            cause = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
            if cause is not None:
                result["cause"] = describe(cause, depth + 1)
            return result

        safe_context = {}
        for key, value in context.items():
            if isinstance(value, str):
                if key == "path":
                    value = value.split("?", 1)[0].split("#", 1)[0]
                safe_context[key] = redact(value)
            elif value is None or isinstance(value, (int, float, bool)):
                safe_context[key] = value
        print(
            json.dumps({"event": event, **safe_context, "error": describe(error)}),
            file=sys.stderr,
            flush=True,
        )
    except Exception:
        # Diagnostics must never replace an operation or cleanup exception.
        pass
