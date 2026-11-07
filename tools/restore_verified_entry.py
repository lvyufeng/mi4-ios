#!/usr/bin/env python3
"""Restore four byte-identical OLD verified entry files; never compile an entry."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

CAP = 64 * 1024 * 1024
ENTRY = tuple('out/stage90/xnu_arm_entry' + s for s in ('.elf', '.bin', '.h', '-config.txt'))
LOCK = 'out/.verified-build.lock'


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relative(root: Path, value: str | Path) -> str:
    p = Path(value)
    if p.is_absolute():
        p = p.relative_to(root)
    require(bool(p.parts) and all(x not in ('', '.', '..') for x in p.parts)
            and str(p) == str(value if not Path(value).is_absolute() else Path(value).relative_to(root)),
            f'noncanonical path: {value}')
    return str(p)


@contextmanager
def parent(root: Path, name: str):
    """Walk every directory using no-follow dirfds, including the root itself."""
    parts = (root / relative(root, name)).parts
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd, parts[-1]
    finally:
        os.close(fd)


def regular(fd: int) -> os.stat_result:
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= CAP,
            'expected nonempty regular file <=64 MiB')
    return info


def read_bytes(root: Path, name: str) -> bytes:
    with parent(root, name) as (directory, leaf):
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = regular(fd)
            data = bytearray()
            while len(data) <= CAP:
                block = os.read(fd, min(1024 * 1024, CAP + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = os.fstat(fd)
            require(len(data) == before.st_size and
                    (before.st_mtime_ns, before.st_ctime_ns, before.st_size) ==
                    (after.st_mtime_ns, after.st_ctime_ns, after.st_size), 'file changed while read')
            return bytes(data)
        finally:
            os.close(fd)


def record(root: Path, name: str, data: bytes | None = None) -> dict:
    data = read_bytes(root, name) if data is None else data
    return {'path': name, 'size': len(data), 'sha256': sha(data)}


def records(items: list) -> dict:
    result = {}
    for item in items:
        name = item['path']
        require(name not in result and isinstance(item['size'], int) and 0 < item['size'] <= CAP
                and isinstance(item['sha256'], str) and len(item['sha256']) == 64
                and all(c in '0123456789abcdef' for c in item['sha256']), 'bad/duplicate hash record')
        result[name] = {k: item[k] for k in ('path', 'size', 'sha256')}
    return result


def checked(root: Path, item: dict) -> bytes:
    data = read_bytes(root, item['path'])
    require(record(root, item['path'], data) == {k: item[k] for k in ('path', 'size', 'sha256')},
            f'hash/size changed: {item["path"]}')
    return data


def new_file(root: Path, name: str, data: bytes) -> None:
    with parent(root, name) as (directory, leaf):
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


@contextmanager
def build_lock(root: Path, held: bool = False):
    with parent(root, LOCK) as (directory, leaf):
        fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                    'unsafe build lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                require(held, 'another verified build owns this repository')
            else:
                require(not held, 'restore requires the builder-held repository lock')
            yield
        finally:
            os.close(fd)


def restore(root: Path, manifest: str, expected: str) -> int:
    root = root.absolute()
    require(root == root.resolve(strict=True), 'root must be canonical')
    run = os.environ.get('MI4_VERIFIED_BUILD_RUN', '')
    require(run and relative(root, run).startswith('out/'), 'restore is builder-stage only')
    with build_lock(root, held=True):
        raw = read_bytes(root, manifest)
        require(sha(raw) == expected, 'snapshot manifest hash changed')
        proof = json.loads(raw)
        require(proof['root'] == str(root) and proof['kind'] == 'payload-only-old-entry-reuse-v1', 'wrong proof')
        pins = records(proof['pins'])
        for item in pins.values():
            checked(root, item)
        artifacts = records(proof['entry'])
        require(set(artifacts) == set(ENTRY), 'restore owns only four exact entry paths')
        cache = records(proof['cache'])
        folder = str(Path(manifest).parent)
        data = {}
        for index, name in enumerate(ENTRY):
            cached = folder + f'/entry-{index}'
            require(cached in cache, 'missing cached entry')
            data[name] = checked(root, cache[cached])
            require(record(root, name, data[name]) == artifacts[name], 'cache not prior entry')
            checked(root, artifacts[name])  # Refuse missing or concurrently replaced live output.
            with parent(root, name) as (directory, leaf):
                info = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                        and info.st_nlink == 1, 'unsafe restore output')
        for name in ENTRY:
            with parent(root, name) as (directory, leaf):
                fd = os.open(leaf, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                with os.fdopen(fd, 'r+b') as stream:
                    info = regular(stream.fileno())
                    require(info.st_uid == os.getuid() and info.st_nlink == 1, 'unsafe restore output')
                    require(sha(stream.read(CAP + 1)) == artifacts[name]['sha256'], 'output changed before write')
                    stream.seek(0)
                    stream.write(data[name])
                    stream.flush()
                    os.fsync(stream.fileno())
                    now = max(time.time_ns(), info.st_mtime_ns + 1)
                    os.utime(stream.fileno(), ns=(now, now))
            checked(root, artifacts[name])
        require(sha(read_bytes(root, manifest)) == expected, 'snapshot changed during restore')
    print('Restored 4 byte-identical OLD verified entry artifacts; NOT freshly compiled.')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        return restore(args.root, args.manifest, args.sha256)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'REFUSING: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
