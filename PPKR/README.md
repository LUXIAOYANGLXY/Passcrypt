-----------------------PPKR------------------------

**Description**

PPKR (Password-Protected Key Retrieval) is a system for securely storing and retrieving a high-entropy data encryption key \(K\) with only a low-entropy password. The implementation follows **"Password-Protected Key Retrieval with(out) HSM Protection"** (Faller et al., ACM CCS 2024).

This repository includes a **Client**, a **TCP Server** , and experiment scripts. Supported operations:

* **Init (Register / Give)**: Client registers under identity `idc` with a password and stores a protected copy of the data encryption key \(K\) via the Server/HSM.
* **Rec (Take)**: Client reconstructs \(K\) from the password and Server/HSM interaction.
* **Secure Deposit**: Client encrypts file data with \(K\) using **AES-256-GCM**.
* **Secure Retrieve**: Client recovers \(K\) via Rec, then decrypts the local ciphertext with AES-256-GCM.


**Installation**

Clone / download the full repository (Client, Server, HSM, and experiments in one tree).

**Requirements**

Software (Client and Server):

* Python 3.8+
* Dependencies in `requirements.txt` (`cryptography`, `pytest`, `openpyxl`)
* System **OpenSSL libcrypto** for P-256 group operations (on Windows often `System32\libcrypto.dll`)

Hardware / deployment:

* Client and Server may run on different machines (recommended for network experiments).
* It is fine to run Server and Client as two processes on one machine for functional checks.

**Preparation**

1. Install Python dependencies from the project root.
2. Ensure the TCP port is free (default `127.0.0.1:8765`), or choose another port on both sides.
3. For remote experiments: deploy this repository on the Server host, open the chosen TCP port in the security group (restrict source IP), and point Client `--host` / `--port` at that endpoint. Optionally use an SSH tunnel instead of a public port.

**Environment Requirements**

```bash
pip install -r requirements.txt
```

* Python 3.8+
* Optional: pytest for unit / wire smoke tests

**Configuration**

Default endpoint (see `common/endpoint.py`):

| Setting | Default |
|---------|---------|
| Host | `127.0.0.1` |
| Port | `8765` |
| Default protocol | `oprf_ppkr` |

Override via CLI:

```bash
python serve.py --host 0.0.0.0 --port 8765
python run_client.py --host <IP> --port 8765 --protocol oprf_ppkr
python -m experiment.tcp_benchmark --host <IP> --port 8765 --trials 20
```

Legacy Flask HTTP (`server/app.py`) is not the default path.


**test datasets**

Experiment 3 uses synthetic binary files from **1 MB to 500 MB** (configurable). Password length is fixed to **16** characters (aligned with PAEE file-size benches).

Generate an `n`-MB file (Windows):

```bat
fsutil file createnew DataFile\nmb.bin 1048576*n
```

Example for 1 MB:

```bat
fsutil file createnew DataFile\1mb 1048576
```

On Linux / macOS:

```bash
dd if=/dev/zero of=DataFile/1mb bs=1M count=1
```

Note: the built-in `file_size_proto_bench` generates in-memory plaintext of the requested size; external files are only needed if you drive a custom client path.

**Run**

From the project root:

**Terminal 1 — Server**

```bash
python serve.py
# remote: python serve.py --host 0.0.0.0 --port 8765
```

**Terminal 2 — Client (smoke)**

```bash
python run_client.py --password mypass --idc alice
```

Local in-process check (no TCP; not for paper latency):

```bash
python run_local.py
```

**Test**

```bash
python -m pytest tests/ -v
```

Functional flow: Init + Rec, key match, wrong-password Fail / DelRec, Schnorr attest, TCP wire encode/decode and OPRF smoke on an ephemeral port.

For timed runs, generate binary files (or use the bench’s in-memory sizes), execute the experiment commands below, and record latency / communication from the MD/CSV/Excel outputs under `experiment/output/`.

**experiment**

Start the Server first (unless using `--auto-server`).

```bash
# Server
python serve.py
# or: python serve.py --host 0.0.0.0 --port 8765
```

Client / measurement (examples):

```bash
# Experiment: Init/Rec latency + wire bytes (aligns with PAEE Enc_proto / Dec_proto)
python -m experiment.tcp_benchmark --trials 100 --host <EC2_IP> --port 8765

# Experiment: password length = 16; Enc_total = Init + local AES-GCM;
python -m experiment.file_size_proto_bench --trials 3 --host <EC2_IP> --port 8765
```

Outputs:

* `experiment/output/tcp_network_benchmark.{md,csv,xlsx}`
* `experiment/output/file_size_proto_benchmark.{md,csv,xlsx}`

**References**

Faller, Ottenbreit, Fischlin. *Password-Protected Key Retrieval with(out) HSM Protection.* ACM CCS 2024.




