#!/usr/bin/env python3
"""
SYN flood experiments (offline, no root needed).
  python synexp.py bench    -> Exp 1: processing ceiling of a Scapy-based detector (packets/sec)
  python synexp.py detect   -> Exp 2: fixed vs adaptive (EWMA) threshold on low-rate SYN floods
  python synexp.py          -> both
Setup: pip install scapy
Outputs: bench_results.csv, detect_results.csv + printed summary tables (paste into paper).
"""
import sys, math, random, time, csv, statistics as st
from collections import defaultdict
from scapy.all import Ether, IP, TCP, PcapWriter, PcapReader, RawPcapReader, sniff, conf

conf.verb = 0
T0 = 1_700_000_000          # fixed epoch offset so 1-second bins are reproducible
DST = "10.0.0.5"


# ---------------------------------------------------------------- traffic generation
def poisson(rng, lam):
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))
    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= L:
            return k
        k += 1


def rip(rng):
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def syn(rng, ts):
    p = Ether() / IP(src=rip(rng), dst=DST) / TCP(sport=rng.randint(1024, 65535), dport=80, flags="S")
    p.time = ts
    return p


def gen_pcap(path, seed, duration=240, base=20, atk_start=120, atk_len=60, atk_rate=0):
    """Benign SYNs ~Poisson(base)/s with three 5 s legit bursts at 3x base (false-positive stress),
    plus optional attack SYNs ~Poisson(atk_rate)/s from spoofed random sources."""
    rng = random.Random(seed)
    # 2 bursts before the attack, 1 after; none overlap the attack window (keeps detection unconfounded)
    bursts = [rng.uniform(15, atk_start - 15), rng.uniform(15, atk_start - 15),
              rng.uniform(atk_start + atk_len + 10, duration - 10)]
    stamps = []
    for s in range(duration):
        lam = base * (3 if any(b <= s < b + 5 for b in bursts) else 1)
        n = poisson(rng, lam)
        if atk_rate and atk_start <= s < atk_start + atk_len:
            n += poisson(rng, atk_rate)
        stamps += [T0 + s + rng.random() for _ in range(n)]
    stamps.sort()
    w = PcapWriter(path, sync=False)
    for ts in stamps:
        w.write(syn(rng, ts))
    w.close()
    return len(stamps)


# ---------------------------------------------------------------- detectors (1-second bins)
class Fixed:
    def __init__(self, T):
        self.T, self.name = T, f"fixed-{T}"

    def step(self, c):
        return c > self.T


class EWMA:
    """Alarm if count > mean + k*max(std,1). Stats frozen during alarms so the attack can't poison the baseline."""

    def __init__(self, k=3.0, alpha=0.1, warm=20):
        self.k, self.a, self.warm = k, alpha, warm
        self.n, self.m, self.v = 0, 0.0, 0.0
        self.name = f"ewma-k{k:g}"

    def step(self, c):
        self.n += 1
        if self.n == 1:
            self.m = c
            return False
        alarm = self.n > self.warm and c > self.m + self.k * max(math.sqrt(self.v), 1.0)
        if not alarm:
            d = c - self.m
            self.m += self.a * d
            self.v = (1 - self.a) * (self.v + self.a * d * d)
        return alarm


def make_dets():
    return [Fixed(50), Fixed(100), EWMA(3), EWMA(5)]


def alarms_from_pcap(path, dets, duration):
    counts = [0] * duration
    for p in PcapReader(path):
        if TCP in p and int(p[TCP].flags) == 0x02:
            b = int(float(p.time) - T0)
            if 0 <= b < duration:
                counts[b] += 1
    return {d.name: [i for i, c in enumerate(counts) if d.step(c)] for d in dets}


# ---------------------------------------------------------------- Exp 2: fixed vs adaptive
def detect(rates=(0, 10, 20, 40, 80, 160), seeds=10, duration=240, a0=120, alen=60):
    rows = []
    for r in rates:
        for sd in range(seeds):
            gen_pcap("tmp.pcap", sd, duration, 20, a0, alen, r)
            for name, al in alarms_from_pcap("tmp.pcap", make_dets(), duration).items():
                if r == 0:  # control run: every alarm is a false positive
                    rows.append(dict(rate=r, seed=sd, det=name, detected="", delay="", fp=len(al)))
                    continue
                inw = [s for s in al if a0 <= s < a0 + alen]
                out = [s for s in al if not (a0 <= s < a0 + alen)]
                rows.append(dict(rate=r, seed=sd, det=name, detected=int(bool(inw)),
                                 delay=(min(inw) - a0) if inw else "", fp=len(out)))
        print(f"  attack rate {r}/s done", flush=True)

    with open("detect_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

    g = defaultdict(list)
    for x in rows:
        g[(x["det"], x["rate"])].append(x)
    benign_secs = duration - alen
    print("\nEXP 2: detector | attack SYN/s | detection % | mean delay (s) | false alarms per 10 min")
    for (det, r), xs in sorted(g.items()):
        fpm = st.mean(x["fp"] for x in xs) / (duration if r == 0 else benign_secs) * 600
        if r == 0:
            print(f"{det:10s} | {r:>4} | {'n/a':>5} | {'n/a':>5} | {fpm:6.1f}")
        else:
            dr = 100 * st.mean(x["detected"] for x in xs)
            dl = [x["delay"] for x in xs if x["delay"] != ""]
            dls = f"{st.mean(dl):5.1f}" if dl else "  -  "
            print(f"{det:10s} | {r:>4} | {dr:5.0f} | {dls} | {fpm:6.1f}")


# ---------------------------------------------------------------- Exp 1: processing ceiling
class Stream:
    """Per-packet detector (what a live Scapy sniff callback would run)."""

    def __init__(self):
        self.cur, self.cnt, self.alarms, self.det = None, 0, 0, Fixed(100)

    def __call__(self, p):
        if TCP in p and int(p[TCP].flags) == 0x02:
            b = int(float(p.time) - T0)
            if self.cur is None:
                self.cur = b
            while b > self.cur:
                self.alarms += self.det.step(self.cnt)
                self.cnt, self.cur = 0, self.cur + 1
            self.cnt += 1


def m_raw(path):
    n = 0
    for pkt, _ in RawPcapReader(path):
        if pkt[14 + (pkt[14] & 0x0F) * 4 + 13] == 0x02:
            n += 1
    return n


def m_reader(path):
    s = Stream()
    for p in PcapReader(path):
        s(p)


def m_sniff(path):
    sniff(offline=path, prn=Stream(), store=False)


def bench(n=100_000, reps=3):
    rng = random.Random(1)
    w = PcapWriter("bench.pcap", sync=False)
    for i in range(n):
        w.write(syn(rng, T0 + i * 1e-4))
    w.close()
    methods = [("raw-bytes (no dissection)", m_raw),
               ("Scapy PcapReader + detector", m_reader),
               ("Scapy sniff(offline) + detector", m_sniff)]
    rows = []
    print(f"\nEXP 1: {n} SYN packets, {reps} reps  |  method | packets/s (mean±sd) | CPU-time/packet (us)")
    for name, fn in methods:
        pps, cpu = [], []
        for _ in range(reps):
            t, c = time.perf_counter(), time.process_time()
            fn("bench.pcap")
            wall, cput = time.perf_counter() - t, time.process_time() - c
            pps.append(n / wall)
            cpu.append(cput / n * 1e6)
            rows.append(dict(method=name, pps=n / wall, cpu_us_per_pkt=cput / n * 1e6))
        sd = st.stdev(pps) if len(pps) > 1 else 0
        print(f"{name:34s} | {st.mean(pps):10.0f} ± {sd:6.0f} | {st.mean(cpu):7.1f}")
    with open("bench_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd in ("bench", "all"):
        bench()
    if cmd in ("detect", "all"):
        detect()
