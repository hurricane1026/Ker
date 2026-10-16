#!/usr/bin/env python3
"""Run Ker against an independent Linux TCP socket in a disposable netns."""
import errno
import fcntl
import os
from pathlib import Path
import shutil
import select
import socket
import struct
import subprocess
import sys
import time


def run(binary, server_first=False, local_port=8000, reorder=False, persist=False, rto=False):
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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
            peer.bind(('192.0.2.2', local_port))
            if persist:
                peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
            peer.settimeout(5)
            mode = 'persist' if persist else ('rto' if rto else
                   ('server-first' if server_first else ('reorder' if reorder else None)))
            child = subprocess.Popen([binary, str(tap)] + ([mode] if mode else []),
                                     pass_fds=(tap,), stdout=subprocess.PIPE if persist else None,
                                     text=persist, bufsize=1 if persist else -1)
            peer.connect(('192.0.2.1', 9000))
            peer.sendall(bytes(range(256)) * 16)
            if not server_first:
                peer.shutdown(socket.SHUT_WR)
            if persist:
                # Keep the peer window closed until Ker emits a real zero-window retry.
                deadline = time.monotonic() + 5
                marker_seen = False
                while time.monotonic() < deadline:
                    ready, _, _ = select.select(
                        [child.stdout], [], [], max(0, deadline - time.monotonic()))
                    if not ready:
                        break
                    line = child.stdout.readline()
                    if not line:
                        break
                    if line.strip() == 'PERSIST_RETRY_AT_ZERO_INITIAL':
                        marker_seen = True
                        break
                assert marker_seen, 'Ker did not emit a zero-window retry before peer read'
            received = bytearray()
            response_length = 65536 if persist else 4096
            while len(received) < response_length:
                part = peer.recv(response_length - len(received))
                if not part:
                    raise AssertionError('peer closed before full-duplex response')
                received.extend(part)
            assert received == bytes((i + 37) & 0xff for i in range(response_length))
            if peer.recv(1) != b'':
                raise AssertionError('expected orderly EOF after passive FIN close')
            if server_first:
                # Observe Ker's FIN/EOF before beginning the peer half-close.
                peer.shutdown(socket.SHUT_WR)
            assert child.wait(timeout=5) == 0
        print(f'PASS: Linux TCP connect, {"server-first" if server_first else "peer-first"}'
              f'{" with proven segment reordering" if reorder else ""} '
              'half-close, full-duplex streams and orderly EOF')
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
        raise SystemExit('usage: tcp-host.py /absolute/path/to/ker-tcp-listener-test')
    if len(sys.argv) == 3 and sys.argv[2] == '--isolated':
        result = run(sys.argv[1], False, 8000)
        if result:
            raise SystemExit(result)
        result = run(sys.argv[1], True, 8001)
        if result:
            raise SystemExit(result)
        result = run(sys.argv[1], False, 8002, reorder=True)
        if result:
            raise SystemExit(result)
        result = run(sys.argv[1], False, 8003, persist=True)
        if result:
            raise SystemExit(result)
        raise SystemExit(run(sys.argv[1], False, 8004, rto=True))
    if len(sys.argv) == 3 and sys.argv[2] == 'persist':
        if not shutil.which('unshare') or not shutil.which('ip'):
            raise SystemExit(77)
        probe = subprocess.run(['unshare', '-Urn', 'true'], capture_output=True, text=True)
        if probe.returncode:
            raise SystemExit(77)
        raise SystemExit(subprocess.call(['unshare', '-Urn', sys.executable,
            str(Path(__file__).resolve()), str(Path(sys.argv[1]).resolve()), 'persist', '--isolated']))
    if len(sys.argv) == 4 and sys.argv[2:] == ['persist', '--isolated']:
        raise SystemExit(run(sys.argv[1], False, 8003, persist=True))
    if len(sys.argv) == 3 and sys.argv[2] == 'rto':
        if not shutil.which('unshare') or not shutil.which('ip'):
            raise SystemExit(77)
        probe = subprocess.run(['unshare', '-Urn', 'true'], capture_output=True, text=True)
        if probe.returncode:
            raise SystemExit(77)
        raise SystemExit(subprocess.call(['unshare', '-Urn', sys.executable,
            str(Path(__file__).resolve()), str(Path(sys.argv[1]).resolve()), 'rto', '--isolated']))
    if len(sys.argv) == 4 and sys.argv[2:] == ['rto', '--isolated']:
        raise SystemExit(run(sys.argv[1], False, 8004, rto=True))
    if not shutil.which('unshare') or not shutil.which('ip'):
        print('SKIP: unshare and ip are required')
        raise SystemExit(77)
    probe = subprocess.run(['unshare', '-Urn', 'true'], capture_output=True, text=True)
    if probe.returncode:
        print(f'SKIP: user/network namespaces unavailable: {probe.stderr.strip()}')
        raise SystemExit(77)
    raise SystemExit(subprocess.call(['unshare', '-Urn', sys.executable,
        str(Path(__file__).resolve()), str(Path(sys.argv[1]).resolve()), '--isolated']))
