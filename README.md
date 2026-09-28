# Lightweight Evaluation of Fixed and EWMA-Based Thresholds for SYN Flood Detection

A lightweight experimental evaluation of fixed-threshold and exponentially weighted moving average (EWMA)-based methods for detecting SYN flood traffic using Python and Scapy.

The project evaluates detection probability, detection delay, false alarms, and packet-processing throughput under controlled synthetic traffic conditions.

## Overview

SYN floods exploit the TCP connection-establishment process by generating large numbers of SYN requests, potentially exhausting server resources.

This project compares four lightweight threshold-based detection configurations:

* Fixed threshold: **50 SYN/s**
* Fixed threshold: **100 SYN/s**
* EWMA threshold: **k = 3**
* EWMA threshold: **k = 5**

The experiments use one-second SYN packet counts and evaluate detector behavior across multiple attack rates.

## Experimental Design

Traffic is generated as synthetic PCAP files using Scapy.

| Parameter                   | Value                     |
| --------------------------- | ------------------------- |
| Total duration              | 240 s                     |
| Attack start                | 120 s                     |
| Attack duration             | 60 s                      |
| Benign baseline             | 20 SYN/s                  |
| Legitimate burst rate       | 60 SYN/s                  |
| Legitimate burst duration   | 5 s                       |
| Number of legitimate bursts | 3                         |
| Attack rates                | 10, 20, 40, 80, 160 SYN/s |
| Trials per attack rate      | 10                        |
| Time-bin size               | 1 s                       |
| Destination                 | 10.0.0.5                  |
| Destination port            | 80                        |

The legitimate bursts are included to stress the detectors with short-term increases in benign SYN traffic.

## Detection Methods

### Fixed Threshold

A fixed detector raises an alarm when the number of SYN packets in a one-second interval exceeds a predefined threshold:

```text
Alarm = 1 if C_t > T
        0 otherwise
```

Two thresholds are evaluated:

* `T = 50`
* `T = 100`

### EWMA-Based Threshold

The adaptive detector estimates the recent mean and variance of the SYN count and raises an alarm when:

```text
C_t > μ_t + k × max(σ_t, 1)
```

The experiments use:

* `α = 0.1`
* Warm-up period = 20 s
* `k = 3`
* `k = 5`

EWMA statistics are frozen during alarm periods so that attack traffic does not immediately inflate the estimated baseline.

## Evaluation Metrics

### Detection Probability

An attack is considered detected if at least one alarm occurs during the 60-second attack interval.

### Detection Delay

Detection delay is the number of seconds between the attack start and the first alarm occurring inside the attack interval.

### False Alarms

False alarms are counted as alarmed one-second bins outside the attack interval.

For comparison, false alarms are normalized to a 10-minute observation period.

### Packet-Processing Throughput

The benchmark compares:

1. Raw PCAP byte processing without packet dissection
2. Scapy `PcapReader` with the detector
3. Scapy `sniff(offline=...)` with the detector

Throughput is reported in packets per second, together with CPU time per packet.

## Results

### Detection Probability

| Detector  | 10 SYN/s | 20 SYN/s | 40 SYN/s | 80 SYN/s | 160 SYN/s |
| --------- | -------: | -------: | -------: | -------: | --------: |
| Fixed-50  |       0% |     100% |     100% |     100% |      100% |
| Fixed-100 |       0% |       0% |       0% |     100% |      100% |
| EWMA-k3   |      80% |     100% |     100% |     100% |      100% |
| EWMA-k5   |       0% |      20% |     100% |     100% |      100% |

### Packet-Processing Benchmark

| Method                          |    Mean throughput |
| ------------------------------- | -----------------: |
| Raw bytes                       | ~691,288 packets/s |
| Scapy PcapReader + detector     |   ~4,994 packets/s |
| Scapy sniff(offline) + detector |   ~4,946 packets/s |

The raw-byte measurement is a low-level processing baseline and is not directly equivalent to the throughput of the packet-dissection-based detector.

The approximately 5,000 packets/s measurements represent the throughput observed for this implementation under the experimental environment and should not be interpreted as a universal Scapy performance limit.

## Experimental Environment

The experiments were executed in a Kaggle notebook.

**Software**

* Python 3.12.13
* Scapy 2.7.0

**CPU**

* Intel(R) Xeon(R) CPU @ 2.20GHz
* 2 physical cores
* 4 logical CPUs
* KVM virtualized environment

## Repository Structure

```text
syn-flood-detection-evaluation/
│
├── synexp.py
├── README.md
├── requirements.txt
├── LICENSE
├── bench_results.csv
└── detect_results.csv
```

## Installation

Clone the repository:

```bash
git clone https://github.com/vamshi1010-cr/syn-flood-detection-evaluation.git
cd syn-flood-detection-evaluation
```

Install the required dependency:

```bash
pip install -r requirements.txt
```

## Running the Experiments

Run both experiments:

```bash
python synexp.py
```

Run only the throughput benchmark:

```bash
python synexp.py bench
```

Run only the detection experiment:

```bash
python synexp.py detect
```

The experiments generate:

```text
bench_results.csv
detect_results.csv
```

Temporary PCAP files are also generated during execution.

## Reproducibility

The experiments use deterministic random seeds for the traffic-generation trials. Ten independent seeds are evaluated for each attack rate.

Because the benchmark depends on the execution environment, throughput values may vary across machines and virtualized environments.

## Limitations

This evaluation uses controlled synthetic traffic rather than traffic captured from a production network.

The experiment also:

* uses a single destination IP and TCP port;
* uses SYN packet counts as the primary detection feature;
* evaluates only four threshold configurations;
* uses 10 trials per attack rate;
* evaluates offline PCAP processing rather than live network capture;
* includes controlled legitimate traffic bursts rather than naturally occurring workload variation.

Therefore, the results demonstrate the behavior of the evaluated implementations under the specified experimental conditions and should not be interpreted as universal performance guarantees.

## Research Context

This repository accompanies the experimental work:

**"Lightweight Evaluation of Fixed and EWMA-Based Thresholds for SYN Flood Detection."**

The repository is intended to support reproducibility of the traffic-generation, detection, and throughput experiments described in the study.

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
