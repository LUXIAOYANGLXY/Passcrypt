# cryptogram (vendored, Windows AES-NI fix)

Upstream: https://github.com/ankit-chaubey/cryptogram (0.1.2)

**Patch:** MSVC builds never defined `__x86_64__`, so `_has_aesni()` always
returned 0 and `get_backend()` stayed `C/table`. Added `__cpuid` path for
`_MSC_VER` + `_M_X64` / `_M_IX86`.

```bash
pip install ./vendor/cryptogram
python -c "import cryptogram; print(cryptogram.has_aesni(), cryptogram.get_backend())"
# expect: True C/AES-NI
```

On Linux (EC2), PyPI `pip install cryptogram` is enough.
