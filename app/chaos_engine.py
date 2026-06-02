import hashlib
from decimal import Decimal, getcontext

getcontext().prec = 20  # High precision for float calculations

def generate_seed(user_id: str, nonce: str, entropy: str) -> float:
    combined = f"{user_id}-{nonce}-{entropy}"
    digest = hashlib.sha256(combined.encode()).hexdigest()
    numeric = int(digest[:16], 16)
    return (numeric % 10**12) / 10**12  # Normalized to [0,1)

def logistic_map(x: float, r: float = 3.99, steps: int = 12) -> float:
    x = Decimal(x)
    r = Decimal(r)
    for _ in range(steps):
        x = r * x * (1 - x)
    return float(x)

def generate_chaos(user_id: str, nonce: str, entropy: str) -> str:
    seed = generate_seed(user_id, nonce, entropy)
    chaos = logistic_map(seed)
    return f"{chaos:.12f}".replace(".", "")[:12]
