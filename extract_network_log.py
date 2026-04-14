#!/usr/bin/env python3
import re
import sys
from pathlib import Path


DEFAULT_LOG = Path("/home/tako/hjyoo/s2e/projects/payload_replay_runtime/run_live.log")

PATTERN = re.compile(
    r"(\[c2pid\] tracking pid="
    r"|\[c2pid\] target-(?:enter|leave)"
    r"|api=(?:WSAStartup|socket|connect|WSAConnect|ioctlsocket|WSAIoctl|select|WSAPoll|WSAWaitForMultipleEvents|"
    r"send|WSASend|recv|WSARecv|closesocket|gethostbyname|gethostbyaddr|gethostname|getservbyname|"
    r"inet_addr|inet_ntoa|htons|htonl|InternetOpenA|InternetConnectA|InternetOpenUrlA|InternetReadFile|"
    r"InternetWriteFile|InternetQueryDataAvailable|HttpQueryInfoA|WinHttpReadData|WSAGetLastError)"
    r"|name=(?:C:\\\\Windows\\\\system32\\\\napinsp\.dll|"
    r"C:\\\\Windows\\\\system32\\\\pnrpnsp\.dll|"
    r"C:\\\\Windows\\\\System32\\\\mswsock\.dll|"
    r"C:\\\\Windows\\\\System32\\\\winrnr\.dll|"
    r"C:\\\\Windows\\\\system32\\\\NLAapi\.dll|"
    r"C:\\\\Windows\\\\system32\\\\wshbth\.dll|"
    r"C:\\\\Windows\\\\System32\\\\rasadhlp\.dll))"
)


def main() -> int:
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LOG
    if not log_path.is_file():
        print(f"log file not found: {log_path}", file=sys.stderr)
        return 1

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            if PATTERN.search(line):
                sys.stdout.write(f"{lineno}:{line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
