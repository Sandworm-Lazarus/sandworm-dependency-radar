"""Bounded local I/O and subprocess helpers; no shell, no raw engine errors."""
from __future__ import annotations
import hashlib, json, os, selectors, signal, stat, subprocess, tempfile, time
from pathlib import Path, PureWindowsPath

MAX_BYTES = 8 * 1024 * 1024
class RadarError(ValueError): pass

def sha256(data): return hashlib.sha256(data).hexdigest()
def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out: raise RadarError("duplicate JSON key")
        out[key] = value
    return out

def parse_json(raw):
    if isinstance(raw, str): raw = raw.encode("utf-8")
    if len(raw) > MAX_BYTES: raise RadarError("input exceeds 8 MiB")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(RadarError("non-finite JSON value")))
        count = 0
        def walk(v, depth=0):
            nonlocal count
            count += 1
            if depth > 48 or count > 200000: raise RadarError("JSON complexity limit")
            if isinstance(v, dict):
                for item in v.values(): walk(item, depth + 1)
            elif isinstance(v, list):
                for item in v: walk(item, depth + 1)
        walk(value)
        return value
    except RadarError: raise
    except (ValueError, UnicodeError, RecursionError): raise RadarError("invalid UTF-8 JSON") from None

def read_json(path):
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        if not stat.S_ISREG(os.fstat(fd).st_mode): raise RadarError("select a regular JSON file")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(MAX_BYTES + 1)
    except OSError: raise RadarError("cannot read selected regular input") from None
    finally:
        if fd is not None: os.close(fd)
    return parse_json(raw), sha256(raw)

def text(v, default="", limit=500):
    if v is None: return default
    if not isinstance(v, str) or len(v) > limit or any(ord(c) < 32 for c in v): raise RadarError("invalid report text")
    return v

def array(v, limit=20000):
    if not isinstance(v, list) or len(v) > limit: raise RadarError("invalid report array")
    return v

def obj(v):
    if not isinstance(v, dict): raise RadarError("expected report object")
    return v

def relative_name(v):
    value = text(v, limit=2000).replace("\\", "/")
    p = Path(value)
    if p.is_absolute() or PureWindowsPath(value).drive or "://" in value or ".." in p.parts: return "[source-path-redacted]"
    return value

def local_target(path, directory=True):
    p = Path(path)
    if p.is_symlink(): raise RadarError("symlink targets are not allowed")
    try: p = p.resolve(strict=True)
    except OSError: raise RadarError("selected target is unavailable") from None
    if directory and not p.is_dir(): raise RadarError("select a local directory")
    if not directory and not p.is_file(): raise RadarError("select a local file")
    if directory:
        count, size = 0, 0
        for root, dirs, files in os.walk(p, followlinks=False):
            for name in dirs + files:
                f = Path(root) / name
                if f.is_symlink(): raise RadarError("target contains symlinks")
            for name in files:
                f = Path(root) / name
                try: s = f.stat().st_size
                except OSError: raise RadarError("target changed during inspection") from None
                if not stat.S_ISREG(f.stat().st_mode): raise RadarError("target contains non-regular files")
                count += 1; size += s
                if count > 10000 or size > 256 * 1024 * 1024: raise RadarError("target exceeds file/size limits")
    elif not stat.S_ISREG(p.stat().st_mode) or p.stat().st_size > 256 * 1024 * 1024: raise RadarError("select a regular target within 256 MiB")
    return p

def run_bounded(argv, timeout=120, limit=MAX_BYTES, env=None):
    if not isinstance(argv, list) or not argv or any(not isinstance(a, str) for a in argv): raise RadarError("invalid engine invocation")
    if not 0 < timeout <= 300: raise RadarError("timeout must be between 1 and 300 seconds")
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, shell=False, start_new_session=True, env=env)
    except OSError: raise RadarError("engine unavailable; install the pinned upstream tool") from None
    sel = selectors.DefaultSelector(); sel.register(proc.stdout, selectors.EVENT_READ, "out"); sel.register(proc.stderr, selectors.EVENT_READ, "err")
    output = bytearray(); total = 0; end = time.monotonic() + timeout
    try:
        while sel.get_map():
            if time.monotonic() > end: raise RadarError("engine timed out")
            for key, _ in sel.select(min(0.2, max(0.001, end-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk: sel.unregister(key.fileobj); continue
                total += len(chunk)
                if total > limit: raise RadarError("engine output limit exceeded")
                if key.data == "out": output.extend(chunk)
        return_code = proc.wait(timeout=max(0.1,end-time.monotonic()))
        return bytes(output), return_code
    except (RadarError, subprocess.TimeoutExpired):
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        proc.wait()
        raise RadarError("engine timed out or exceeded output limits") from None
    finally:
        sel.close(); proc.stdout.close(); proc.stderr.close()

def write_report(path, report, inputs=()):
    dest = Path(path)
    if any(dest.resolve() == Path(p).resolve() for p in inputs): raise RadarError("output must differ from input")
    tmp = None
    try:
        data = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if len(data.encode()) > MAX_BYTES: raise RadarError("report exceeds output limit")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=dest.parent, prefix=".sandworm-report-", delete=False) as stream:
            tmp = Path(stream.name)
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        # link(2) creates an exclusive final name atomically. Never replaces an input,
        # existing report, symlink or a file created by another process during writing.
        os.link(tmp, dest)
    except OSError: raise RadarError("cannot create report; output must be a new file") from None
    finally:
        if tmp is not None:
            try: tmp.unlink()
            except OSError: pass
