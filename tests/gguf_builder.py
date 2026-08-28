import struct
from pathlib import Path


def s(v):
    b = v.encode()
    return struct.pack("<Q", len(b)) + b


def kv(k, t, v):
    return s(k) + struct.pack("<I", t) + v


def sv(v):
    return s(v)


def build(
    path,
    *,
    name="m",
    arch="llama",
    tmpl=None,
    extra=None,
    tensors=None,
    alignment=32,
    version=3,
    tcount=None,
    arr=None,
):
    tensors = tensors or [("blk.0.attn_q.weight", (32, 32), 0)]  # F32
    md = [
        kv("general.architecture", 8, sv(arch)),
        kv("general.name", 8, sv(name)),
        kv("general.alignment", 4, struct.pack("<I", alignment)),
    ]
    if tmpl is not None:
        md.append(kv("tokenizer.chat_template", 8, sv(tmpl)))
    if arr is not None:
        # arr = (key, elem_type, [values as bytes])
        k, et, vals = arr
        md.append(
            s(k)
            + struct.pack("<I", 9)
            + struct.pack("<I", et)
            + struct.pack("<Q", len(vals))
            + b"".join(vals)
        )
    for e in extra or []:
        md.append(e)
    p = [
        b"GGUF",
        struct.pack("<I", version),
        struct.pack("<Q", len(tensors) if tcount is None else tcount),
        struct.pack("<Q", len(md)),
    ] + md
    # descriptors with computed contiguous offsets
    SIZES = {0: (1, 4), 1: (1, 2), 12: (256, 144)}
    off = 0
    sizes = []
    for tn, dims, tt in tensors:
        bs, ts = SIZES[tt]
        n = (dims[0] // bs) * ts
        for d in dims[1:]:
            n *= d
        p.append(
            s(tn)
            + struct.pack("<I", len(dims))
            + b"".join(struct.pack("<Q", d) for d in dims)
            + struct.pack("<I", tt)
            + struct.pack("<Q", off)
        )
        sizes.append(n)
        off += n + (-n % alignment)
    body = b"".join(p)
    pad = (-len(body)) % alignment
    data = bytearray()
    for n in sizes:
        data += b"\x00" * n
        data += b"\x00" * ((-n) % alignment)
    Path(path).write_bytes(body + b"\x00" * pad + bytes(data))
    return Path(path).stat().st_size
