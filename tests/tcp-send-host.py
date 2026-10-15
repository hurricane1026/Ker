#!/usr/bin/env python3
"""Run Ker against an independent Linux TCP socket in a disposable netns."""
import errno
import fcntl
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys


def run(binary, mode=None):
    try:
        tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        # TUNSETIFF, IFF_TAP | IFF_NO_PI: raw Ethernet frames, no PI header.
        fcntl.ioctl(tap, 0x400454CA, struct.pack('16sH', b'kerhost0', 0x1002))
    except OSError as error:
        if error.errno in (errno.EPERM, errno.EACCES, errno.ENOENT, errno.ENODEV):
            print(f'SKIP: TAP unavailable: {error}', flush=True)
            return 77
        raise
    child = None
    try:
        subprocess.run(['ip', 'link', 'set', 'kerhost0', 'address', '02:20:00:00:00:01'], check=True)
        subprocess.run(['ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'kerhost0'], check=True)
        subprocess.run(['ip', 'link', 'set', 'kerhost0', 'mtu', '1500', 'up'], check=True)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(('192.0.2.2', 8000))
            server.listen(1)
            server.settimeout(5)
            child_args = [binary, str(tap)] + ([mode] if mode else [])
            child = subprocess.Popen(child_args, pass_fds=(tap,))
            peer, address = server.accept()
            with peer:
                assert address == ('192.0.2.1', 9000), address
                peer.settimeout(10)
                expected = bytes(i % 251 for i in range(8192))
                received = bytearray()
                while len(received) < len(expected):
                    block = peer.recv(8192 - len(received))
                    assert block, 'premature EOF'
                    received.extend(block)
                assert received == expected
                peer.sendall(expected)
                try:
                    data = peer.recv(1)
                    raise AssertionError(f'expected RST, received {data!r}')
                except ConnectionResetError:
                    pass
            assert child.wait(timeout=5) == 0
        print('PASS: Ker sends 8192 binary bytes, Linux verifies and echoes every byte, ARP and RST')
        return 0
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        os.close(tap)


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3, 4):
        raise SystemExit('usage: tcp-send-host.py binary [rto] [--isolated]')
    mode = sys.argv[2] if len(sys.argv) >= 3 and sys.argv[2] != '--isolated' else None
    isolated = '--isolated' in sys.argv[2:]
    if mode not in (None, 'rto'):
        raise SystemExit(f'unknown mode: {mode}')
    if isolated:
        raise SystemExit(run(sys.argv[1], mode))
    if not shutil.which('unshare') or not shutil.which('ip'):
        print('SKIP: unshare and ip are required')
        raise SystemExit(77)
    probe = subprocess.run(['unshare', '-Urn', 'true'], capture_output=True, text=True)
    if probe.returncode:
        print(f'SKIP: user/network namespaces unavailable: {probe.stderr.strip()}')
        raise SystemExit(77)
    child_args = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
        str(Path(sys.argv[1]).resolve())]
    if mode:
        child_args.append(mode)
    child_args.append('--isolated')
    raise SystemExit(subprocess.call(child_args))
