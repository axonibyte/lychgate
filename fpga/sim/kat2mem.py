#!/usr/bin/env python3
"""Convert wire KAT records into soc-harness inputs.

  kat2mem.py token  <file.kat> <record-name> <out.hex>   -> prints TOKEN_LEN
  kat2mem.py elf2hex <fw.elf> <out.hex>                  -> 32-bit LE words

The .kat parser is the same flat format every consumer duplicates on
purpose (TESTING.md's source-not-re-export rule)."""
import struct
import sys


def records(path):
    rec = {}
    for line in open(path):
        line = line.strip()
        if line.startswith("#"):
            continue
        if not line:
            if rec:
                yield rec
                rec = {}
            continue
        k, _, v = line.partition("=")
        rec[k.strip()] = v.strip()
    if rec:
        yield rec


def cmd_token(kat, name, out):
    for rec in records(kat):
        if rec.get("name") == name:
            token = rec["token"].encode()
            with open(out, "w") as f:
                for b in token:
                    f.write(f"{b:02x}\n")
            print(len(token))
            return 0
    print(f"no record {name!r} in {kat}", file=sys.stderr)
    return 1


def cmd_elf2hex(elf_path, out):
    data = open(elf_path, "rb").read()
    assert data[:4] == b"\x7fELF", "not an ELF"
    assert data[4] == 1 and data[5] == 1, "expected ELF32 LE"
    e_phoff, = struct.unpack_from("<I", data, 28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    image = bytearray()
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, _, p_filesz, p_memsz = struct.unpack_from(
            "<IIIIII", data, off
        )
        if p_type != 1:  # PT_LOAD
            continue
        end = p_vaddr + p_memsz
        if end > len(image):
            image.extend(b"\x00" * (end - len(image)))
        image[p_vaddr : p_vaddr + p_filesz] = data[p_offset : p_offset + p_filesz]
    while len(image) % 4:
        image.append(0)
    with open(out, "w") as f:
        for i in range(0, len(image), 4):
            (word,) = struct.unpack_from("<I", image, i)
            f.write(f"{word:08x}\n")
    print(f"{len(image)} bytes", file=sys.stderr)
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "token":
        sys.exit(cmd_token(*sys.argv[2:5]))
    if sys.argv[1] == "elf2hex":
        sys.exit(cmd_elf2hex(*sys.argv[2:4]))
    sys.exit(2)
