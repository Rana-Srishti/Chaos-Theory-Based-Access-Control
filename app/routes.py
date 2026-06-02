from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from app.token_manager import create_chaos_token
from app.validator import verify_chaos_token
from fastapi import Header

router = APIRouter()

class LoginRequest(BaseModel):
    user_id: str

@router.post("/login")
async def login(data: LoginRequest):
    token = create_chaos_token(data.user_id).decode("utf-8")
    return JSONResponse(content={"token": token}, status_code=200)

@router.post("/verify")
async def verify_access(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        return JSONResponse(content={"error": "Missing token"}, status_code=400)

    token = authorization.split("Bearer ")[1]
    is_valid = verify_chaos_token(token)

    if is_valid:
        return JSONResponse(content={"status": "Access Granted"}, status_code=200)
    else:
        return JSONResponse(content={"status": "Access Denied"}, status_code=401)
