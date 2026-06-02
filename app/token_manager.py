import os
import secrets
from datetime import datetime, timedelta, timezone
from jose import jwt, jwe
from jose.constants import ALGORITHMS
from app.chaos_engine import generate_chaos
from dotenv import load_dotenv

load_dotenv()
JWT_EXPIRY_MINUTES = 5

with open("keys/keys/public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

with open("keys/keys/private.pem", "rb") as f:
    PRIVATE_KEY = f.read()

def generate_nonce(length: int = 16) -> str:
    return secrets.token_hex(length // 2)

def generate_entropy() -> str:
    # Use UTC explicitly
    return str(int(datetime.now(timezone.utc).timestamp() * 1000))[-6:]

def create_chaos_token(user_id: str, expires_in_minutes: int = JWT_EXPIRY_MINUTES) -> str:
    nonce = generate_nonce()
    entropy = generate_entropy()
    chaos_value = generate_chaos(user_id, nonce, entropy)

    # Use UTC timezone explicitly and add some buffer for clock skew
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(minutes=expires_in_minutes)
    
    payload = {
        "user_id": user_id,
        "nonce": nonce,
        "entropy": entropy,
        "chaos": chaos_value,
        "exp": int(expiry.timestamp()),
        "iat": int(now.timestamp()),  # Add issued at time
        "nbf": int(now.timestamp())   # Add not before time
    }

    signed_token = jwt.encode(payload, os.getenv("SECRET_KEY"), algorithm="HS256")

    encrypted_token = jwe.encrypt(
        signed_token,
        PUBLIC_KEY,
        algorithm=ALGORITHMS.RSA_OAEP,
        encryption=ALGORITHMS.A256GCM
    )

    print(f"[Token Gen] nonce: {nonce}")
    print(f"[Token Gen] entropy: {entropy}")
    print(f"[Token Gen] chaos: {chaos_value}")
    print(f"[Token Gen] issued at: {now}")
    print(f"[Token Gen] expires at: {expiry}")
    print(f"[Token Gen] current timestamp: {now.timestamp()}")
    print(f"[Token Gen] expiry timestamp: {expiry.timestamp()}")

    return encrypted_token