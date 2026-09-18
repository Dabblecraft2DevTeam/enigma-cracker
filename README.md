# Enigma Cracker

A modern brute-force cracker for WWII Enigma M3 and M4 (Naval) cipher machines.

## Features

- **Full Enigma M3 and M4 simulation** — all standard rotors (I-VIII, beta, gamma), reflectors (B, C, B_thin, C_thin), and plugboard
- **Brute-force cryptanalysis** — searches all rotor permutations × positions × ring settings
- **Fitness functions** — Index of Coincidence + German trigram/bigram scoring
- **Hill climbing** — optimizes plugboard settings for top candidates
- **OpenMP parallelism** — uses all CPU cores for fast cracking
- **Tkinter GUI** — paste ciphertext, select M3/M4, crack with progress indicator
- **Cross-platform** — Linux (gcc), Windows (MinGW or standalone .exe)

## Performance

| Mode | Configs | Single-thread | 24 threads |
|------|---------|--------------|------------|
| M3 | 2.1M | ~12s | ~2s |
| M4 | 109M | ~12 min | ~40s |

## Files

- `enigma_cracker.c` — C implementation of Enigma simulator + brute-force cracker (with OpenMP)
- `enigma_gui.py` — Tkinter GUI wrapper (auto-compiles the C program)
- `enigma_cracker.py` — Python prototype (slower, for reference)

## Usage

### GUI (recommended)
```bash
python enigma_gui.py
```
The GUI auto-compiles the C binary on first run using gcc (Linux) or MinGW (Windows).

### Command line
```bash
# Self-test (encrypt + crack)
./enigma_cracker

# Crack an M3 message
./enigma_cracker --ct CIPHERTEXT --mode M3

# Crack an M4 Naval message
./enigma_cracker --ct CIPHERTEXT --mode M4

# JSON output for scripting
./enigma_cracker --ct CIPHERTEXT --mode M3 --format json
```

### Build from source
```bash
gcc -O3 -fopenmp -o enigma_cracker enigma_cracker.c -lm
```

## Verified against

- **U-264 message** (Nov 1942, M4 Naval Enigma) — decrypted correctly, matches M4 Project result
- **Self-test** — encrypts a known German message, then cracks it from ciphertext only (no settings provided)

## Why Enigma is trivially crackable today

Enigma's keyspace (~10^23 for 4-rotor) sounds large, but structural weaknesses (no letter encrypts to itself, known plaintext patterns, reused daily keys) reduce the effective search space dramatically. A modern CPU brute-forces M3 in seconds. GPT-6 taking 10 hours to crack Enigma was the LLM reasoning through the problem — not computational difficulty. A purpose-built cracker does it in seconds.

## License

MIT