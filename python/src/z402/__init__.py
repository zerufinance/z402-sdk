"""z402: before an x402 agent pays a wallet, ask zScreen: PAY or DON'T PAY.

    from x402 import x402Client
    import z402

    client = x402Client()
    register_exact_evm_client(client, signer)
    z402.guard(client)                                   # every list blocked (default)
    z402.guard(client, block=["sanctioned", "scams"])    # or only the lists you choose

DON'T PAY raises Z402Blocked before anything is signed. Sellers: z402.seller_guard(server).
"""
from .check import (DEFAULT_BASE_URL, DEFAULT_TIMEOUT_S, GROUPS, KEY_URL, AsyncCheckClient,
                    CheckClient, CheckResult, CheckUnavailable, InsecureURL, MissingAPIKey)
from .errors import Z402Blocked, find_block
from .guard import Decision, decide, guard
from .seller import seller_guard

__version__ = "0.1.0"

__all__ = [
    "guard", "seller_guard", "GROUPS", "DEFAULT_BASE_URL", "DEFAULT_TIMEOUT_S", "KEY_URL",
    "Decision", "decide", "Z402Blocked", "find_block",
    "CheckClient", "AsyncCheckClient", "CheckResult", "CheckUnavailable",
    "MissingAPIKey", "InsecureURL",
]
