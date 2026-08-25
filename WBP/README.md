-----------------------WBP------------------------

Description

WBP (WhatsApp Backup Protocol) is a baseline implementation of the end-to-end encrypted backup protocol analyzed by Davies et al. (CRYPTO 2023 / ePrint 2023/843). With this system, a user can use one low-entropy password to store and later recover a high-entropy backup key (K) at any device. The plaintext backup key and file data are visible only to the legitimate client with the correct password, and remain blind to the relay Server (and, in the paper model, to the service provider except through an HSM).

Our implementation includes a Client and a Server. The supported operations are:
Init (Give key): Client samples backup key (K), runs OPAQUE registration, wraps (K) under K_export (AES-GCM), wraps the envelope under HSM public-key encryption (RSA-OAEP), and stores the record on the HSM via the Server.
Rec / Recovery (Take key): Client reconstructs (K) with the password via OPAQUE login; HSM returns a session-wrapped blob; Client unwraps to obtain (K).
Secure Deposit (file encrypt): Client encrypts a file with (K) using AES-256-GCM.
Secure Retrieve (file decrypt): Client decrypts the file with the recovered (K).

Installation

Download / clone the full repository for both the Client and the Server.

Requirements

Software requirements on both Client and Server:

Python 3.8+
Hardware / deployment:

Client and Server can be deployed on different machines for standard use (e.g. Server on AWS EC2, Client on a lab PC).
It is OK to run two processes (Server + Client) on one device to verify functionality.

Preparation

Please make sure the above requirements are satisfied first and prepare the following.

Dependencies:

cd WBPv1
pip install -r requirements.txt
Dependencies (requirements.txt):

cryptography ≥ 42
opaque-snake ≥ 0.1.1 (Rust opaque-ke)
openpyxl ≥ 3.1 (experiment Excel export)
Network:

For localhost tests, nothing else is required.
For WAN tests (Server on EC2): open the TCP port in the security group; start Server with --host 0.0.0.0.

Environment Requirements

Python 3.8+
Dependencies (see requirements.txt):
pip install -r requirements.txt

Configuration

No config.properties file. Connection is configured by CLI flags:

Flag	Default	Meaning
--host	127.0.0.1	Server bind (Server) or Server address (Client / experiments)
--port	8765	TCP port
--idc	user-demo	Client identity (IDC)
--password	demo-password	Password


Server examples:

# localhost
python run_server.py --host 127.0.0.1 --port 8765

# EC2 / LAN (must listen on all interfaces)
python run_server.py --host 0.0.0.0 --port 8765

Test datasets

The file-size experiments use random binary payloads ranging from 1 MB to 500 MB (generated in memory by the benchmark scripts).

Optional: generate an on-disk n MB file (Windows):

fsutil file createnew 1mb 1048576
fsutil file createnew 10mb 10485760
(Linux/macOS: dd if=/dev/urandom of=10mb bs=1M count=10)


Run

Terminal 1 — Server:

python run_server.py
# or: python run_server.py --host 0.0.0.0 --port 8765
Terminal 2 — Client:

python run_client.py --idc demo-user --password demo-password --mode both
Modes: init | recover | both.

One-shot demo (starts Server + Client):

python scripts/run_demo.py
If port 8765 is occupied:

python run_server.py --port 8876
python run_client.py --port 8876 --mode both

On success, Init and Recovery must return the same backup_key (hex of (K)).

Test

Functional check:

python run_server.py --port 8765
python run_client.py --host 127.0.0.1 --port 8765 --mode both

Wire codec unit tests:

python -m pytest tests/test_wire_codec.py -q
Generate binary sizes from 1 MB to 200/500 MB via the file-size experiment scripts below, run them, and record execution time (and communication bytes where reported).

Experiment

Start Server first (local or EC2):

python run_server.py --host 0.0.0.0 --port 8765

Then on the Client machine:

# Baseline: Init≈Enc_proto / Rec≈Dec_proto — latency + communication
python -m experiment.tcp_benchmark --trials 20 --host <EC2_IP> --port 8765 -q

# Experiment 1: password length scan (L = 8…512)
python -m experiment.password_length_bench --trials 20 --host <EC2_IP> --port 8765 -q

# Experiment 3: file size vs Enc/Dec (password length fixed = 16)
python -m experiment.file_size_proto_bench --trials 3 --host <EC2_IP> --port 8765 -q

# Optional: file AE after key retrieval / end-to-end key+file
python -m experiment.file_encrypt_bench --trials 5 --sizes 1 10 100 --host <EC2_IP> --port 8765 -q
python -m experiment.e2e_key_file_bench --trials 5 --sizes 1 10 100 --host <EC2_IP> --port 8765 -q

Localhost examples:

python -m experiment.tcp_benchmark --trials 20 --host 127.0.0.1 --port 8765 -q
python -m experiment.password_length_bench --trials 20 --host 127.0.0.1 --port 8765 -q
python -m experiment.file_size_proto_bench --trials 3 --host 127.0.0.1 --port 8765 -q

Outputs are written under experiment/output/ (.xlsx / .md / .csv).











