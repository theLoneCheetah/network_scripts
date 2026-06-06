#!/usr/bin/python3
import re

ru_windows_regex = re.compile(r"Ответ от (?P<ip>(?:\d+\.){3}\d+): число байт=(?P<bytes>\d+) время=(?P<time>\d+)мс TTL=(?P<ttl>\d+)\n")
en_linux_regex = re.compile(r"(?P<bytes>\d+) bytes from (?P<ip>(?:\d+\.){3}\d+): icmp_seq=(?:\d+) ttl=(?P<ttl>\d+) time=(?P<time>[\d.]+) ms\n")

count = 0
lost = 0
min_time = float("inf")
max_time = 0
sum_time = 0
results = []

for line in open("v2/ping_result.txt", "r", encoding="utf-16"):
    match = re.match(en_linux_regex, line)
    count += 1

    if match is None:
        lost += 1
        continue
    
    stats = {
        key: value if key == "ip" else float(value) if key == "time" else int(value)
        for key, value in match.groupdict().items()
    }
    results.append(stats)

    min_time = min(min_time, stats["time"])
    max_time = max(max_time, stats["time"])
    sum_time += stats["time"]

if results:
    print(f"""Ping statistics:
IP: {results[0]["ip"]}, bytes: {results[0]["bytes"]}, TTL: {results[0]["ttl"]}
Packets received: {count - lost}/{count}, {lost / count:.2%} loss
Time min/aver/max: {min_time}/{sum_time / count:.2f}/{max_time}ms""")