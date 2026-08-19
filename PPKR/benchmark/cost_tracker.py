"""逻辑操作成本审计 — 对齐论文 Table 3/4 与本实现实测值。

Cost Audit 流程（由 ``experiment/compare.py`` 调用）::

    1. ``experiment/runners`` 在每次 Init/Rec 后收集 Client/HSM 的 ``CostCounter``
    2. ``aggregate_trials`` 对多轮 trial 取平均
    3. ``audit_trial_costs`` 将平均计数与 ``PAPER_EXPECTED`` 逐字段比对
    4. ``format_cost_audit`` 输出 OK / MISMATCH 摘要

与论文 Table 3/4 的差异说明：
    - DHIES (Table 4 AE)：仅 AES-256-GCM；临时公钥作 GCM AAD；KDF 计 hash=3
    - HSM 认证：Schnorr 签/验各计 sig=1（同时跟踪 exp/hash）
    - OPRF H1：RFC9380 hash_to_curve（每次盲化 hash=1, mult=1）
    - Exp/Mult/Hash/AES/Sig 为逻辑操作次数，非 wall-clock 时间

``PAPER_EXPECTED`` 数值来自 ``experiment.runners`` 一次成功 Init+Rec 的实测标定。
"""

from __future__ import annotations

from config import CostCounter

# 本实现标定的期望逻辑操作计数（Init/Rec × Client/HSM）
PAPER_EXPECTED = {
    "encpw_plus": {
        "init_client": CostCounter(exp=6, mult=2, hash=5, aes=1, sig=2),
        "init_hsm": CostCounter(exp=2, hash=6, aes=1, sig=1),
        "rec_client": CostCounter(exp=6, mult=2, hash=5, aes=2, sig=2),
        "rec_hsm": CostCounter(exp=2, hash=6, aes=2, sig=1),
        "init_rounds": 3,
        "rec_rounds": 3,
    },
    "oprf_ppkr": {
        "init_client": CostCounter(exp=9, mult=3, hash=7, aes=2, sig=2),
        "init_hsm": CostCounter(exp=5, hash=5, aes=1, sig=2),
        "rec_client": CostCounter(exp=7, mult=3, hash=5, aes=1, sig=3),
        "rec_hsm": CostCounter(exp=5, mult=1, hash=3, sig=3),
        "init_rounds": 3,
        "rec_rounds": 3,
    },
}


def compare_cost(protocol: str, role: str, phase: str, actual: CostCounter) -> dict:
    """将实测 ``CostCounter`` 与 ``PAPER_EXPECTED`` 中对应项比对。

    Args:
        protocol: 协议名（``encpw_plus`` / ``oprf_ppkr``）
        role: ``client`` 或 ``hsm``
        phase: ``init`` 或 ``rec``
        actual: 实测逻辑操作计数

    Returns:
        含 expected、actual、match 字段的字典
    """
    expected = PAPER_EXPECTED[protocol][f"{phase}_{role}"]
    return {
        "protocol": protocol,
        "role": role,
        "phase": phase,
        "expected": expected.to_dict(),
        "actual": actual.to_dict(),
        "match": actual.to_dict() == expected.to_dict(),
    }


def audit_trial_costs(
    protocol: str,
    init_client: CostCounter,
    init_hsm: CostCounter,
    rec_client: CostCounter,
    rec_hsm: CostCounter,
) -> list[dict]:
    """对一次 trial（或聚合平均）的四组角色成本执行完整 audit。

    Returns:
        四行 compare_cost 结果（init/client, init/hsm, rec/client, rec/hsm）
    """
    rows = []
    for phase, role, actual in (
        ("init", "client", init_client),
        ("init", "hsm", init_hsm),
        ("rec", "client", rec_client),
        ("rec", "hsm", rec_hsm),
    ):
        rows.append(compare_cost(protocol, role, phase, actual))
    return rows


def format_cost_audit(rows: list[dict]) -> str:
    """将 audit 结果格式化为多行文本（OK / MISMATCH 标记）。"""
    lines = ["Cost audit (logical ops vs PAPER_EXPECTED):"]
    for r in rows:
        status = "OK" if r["match"] else "MISMATCH"
        lines.append(
            f"  [{status}] {r['protocol']} {r['phase']}/{r['role']}: "
            f"expected={r['expected']} actual={r['actual']}"
        )
    return "\n".join(lines)
