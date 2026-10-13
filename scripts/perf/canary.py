import sys, time
# Logs every wall-clock gap over 0.5 s in a loop that sleeps 0.1 s: a host or scheduler freeze shows up here.
out = open(sys.argv[1], "w", buffering=1)
last = time.monotonic()
while True:
    time.sleep(0.1)
    now = time.monotonic()
    if now - last > 0.5:
        out.write(f"{time.strftime('%H:%M:%S')} gap_s={now-last:.2f}\n")
    last = now
