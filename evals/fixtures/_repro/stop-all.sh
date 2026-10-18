#!/usr/bin/env bash
# Stop every fixture process listening on the fixture port range (3101-3199).
for port in $(seq 3101 3199); do
  pid=$(ss -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {print $6}' | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
  [ -n "$pid" ] && kill $pid 2>/dev/null
done
exit 0
