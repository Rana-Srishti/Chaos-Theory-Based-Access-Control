import os
from jose import jwt, jwe
from jose.constants import ALGORITHMS
from datetime import datetime, timezone
from dotenv import load_dotenv
from app.chaos_engine import generate_chaos

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")

# Load RSA private key for JWE decryption
with open("keys/keys/private.pem", "rb") as f:
    PRIVATE_KEY = f.read()

def verify_chaos_token(encrypted_token: str) -> bool:
    try:
        # Step 1: Decrypt the encrypted JWE token
        signed_token = jwe.decrypt(encrypted_token, PRIVATE_KEY).decode("utf-8")
        print("Decrypted signed JWT:", signed_token)

        # Step 2: Decode the signed JWT with proper options
        payload = jwt.decode(
            signed_token, 
            SECRET_KEY, 
            algorithms=["HS256"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "require_exp": True,
                "require_iat": True,
                "require_nbf": True,
                "leeway": 10  # 10 second leeway for clock skew
            }
        )
        print("Decoded Payload:", payload)

        # Step 3: Extract required fields
        user_id = payload.get("user_id")
        nonce = payload.get("nonce")
        entropy = payload.get("entropy")
        token_chaos = payload.get("chaos")
        expiry = payload.get("exp")
        issued_at = payload.get("iat")

        # Step 4: Basic payload validation
        if not all([user_id, nonce, entropy, token_chaos, expiry]):
            print("Invalid payload structure.")
            return False

        # Step 5: Manual time check with explicit UTC (as backup)
        current_time = datetime.now(timezone.utc).timestamp()
        print(f"Current time: {current_time}")
        print(f"Token expiry: {expiry}")
        print(f"Token issued at: {issued_at}")
        print(f"Time until expiry: {expiry - current_time} seconds")
        
        if current_time > expiry:
            print("Token expired (manual check).")
            return False

        # Step 6: Recompute chaos value
        expected_chaos = generate_chaos(user_id, nonce, entropy)

        print("User ID:", user_id)
        print("Nonce:", nonce)
        print("Entropy:", entropy)
        print("Chaos from token:", token_chaos)
        print("Recomputed chaos:", expected_chaos)

        # Step 7: Match chaos values
        return str(expected_chaos) == str(token_chaos)

    except jwt.ExpiredSignatureError:
        print("Token has expired (JWT validation).")
        return False
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return False
    except Exception as e:
        print(f"Token validation error: {e}")
        return False