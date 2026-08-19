"""
WBP protocol notes (Davies et al. Crypto'23, Figures 4 and 5).

Deployment note: HSM runs as an in-process module inside Server (same crypto
API surface as a remote HSM). Networking Client↔Server uses TCP+HELLO in place
of Noise; Server↔HSM is a direct function call instead of TLS.

Fig.4 Initialization (logical steps):
  1. Client: K ←$ {0,1}^λ; OPAQUE RegStart(pw) → a1
  2. Server: aid_new, relay (aid, a1) to HSM
  3. HSM: OPAQUE RegEval → (b1, n1, σ); tr_HSM ← H3(a1,b1,n1)
  4. Client: verify σ; OPAQUE RegFinish → K_export;
             e ← AE.Enc(K_export, K);
             tr_C ← H3(a1,b1,n1); E ← PKE.Enc(pk_Enc, e∥tr_C);
             send E + RegistrationUpload
  5. HSM: m ← PKE.Dec(E); check tr; store (password_file, e, ctr=10)

Fig.5 Recovery:
  1. Client: OPAQUE LoginStart(pw') → a2
  2. HSM: load record; if ctr=0 delete; else ctr--; OPAQUE LoginEval
  3. Client: verify σ; OPAQUE LoginFinish → (K_export, shk); send finalization
  4. HSM: OPAQUE confirm; ctr←10; c ← AE.Enc(shk, e)
  5. Client: e ← AE.Dec(shk, c); K ← AE.Dec(K_export, e)

OPAQUE core is opaque-ke via opaque-snake (same family as WhatsApp's audited stack).
"""
