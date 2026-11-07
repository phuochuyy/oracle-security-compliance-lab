#!/usr/bin/env python3
"""Off-host copy of Unified Audit records: a small TCP syslog receiver on the KVM host, standing in for a central log server.

A DBA with SYS can purge AUDSYS. Once a record has left the machine, that same DBA cannot take it back, which is the point of
PCI-DSS 10.3.3. Each sending host gets its own file per day. Only the lab's VM networks may connect.
No TLS here: a real receiver would use TLS or RELP, and would be run by someone other than the DBAs.

usage: audit_receiver.py <directory> [port]     (default port 5514)
"""
import datetime
import ipaddress
import pathlib
import socketserver
import sys

ALLOWED = [ipaddress.ip_network(n) for n in ("192.168.104.0/24", "192.168.105.0/24", "192.168.106.0/24", "192.168.107.0/24")]
OUT = pathlib.Path(sys.argv[1])
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5514


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        if not any(ipaddress.ip_address(ip) in n for n in ALLOWED):
            print(f"refused {ip}", flush=True)
            return
        for raw in self.rfile:
            line = raw.decode("utf-8", "replace").rstrip()
            if not line:
                continue
            day = datetime.date.today().strftime("%Y%m%d")
            with open(OUT / f"{ip}-{day}.log", "a", encoding="utf-8") as f:
                f.write(line + "\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    with Server(("0.0.0.0", PORT), Handler) as s:
        s.serve_forever()
