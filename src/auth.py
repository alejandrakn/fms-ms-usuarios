"""Login y validación de token. `validar` es la Lambda fsm-<stage>-validar-token que invocan los 5 MS."""
import hashlib
import hmac
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

from src.comun import ErrorHttp, cuerpo, log, manejar, respuesta, tabla, token_de_headers


def hash_password(password, salt_hex=None):
    """PBKDF2-SHA256 con salt. Retorna (salt_hex, hash_hex)."""
    salt = salt_hex or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000).hex()
    return salt, h


def _iso(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolver_token(token):
    """Devuelve {tenant_id, user_id, rol} si el token existe y no venció; si no, ErrorHttp 403."""
    if not token:
        raise ErrorHttp(403, "Falta el token")
    item = tabla("TABLA_TOKENS").get_item(Key={"token": token}).get("Item")
    if not item:
        raise ErrorHttp(403, "Token no existe")
    if int(item["expires_epoch"]) < time.time():
        raise ErrorHttp(403, "Token expirado")
    return {"tenant_id": item["tenant_id"], "user_id": item["user_id"], "rol": item["rol"]}


@manejar
def login(event):
    """POST /usuarios/login  {tenant_id, user_id, password} -> token con expiración."""
    b = cuerpo(event)
    tenant_id, user_id, password = b.get("tenant_id"), b.get("user_id"), b.get("password")
    if not (isinstance(tenant_id, str) and isinstance(user_id, str) and isinstance(password, str)
            and tenant_id and user_id and password):
        raise ErrorHttp(400, "Se requiere tenant_id, user_id y password")
    usuario = tabla("TABLA_USUARIOS").get_item(Key={"tenant_id": tenant_id, "user_id": user_id}).get("Item")
    if not usuario or not hmac.compare_digest(hash_password(password, usuario["salt"])[1],
                                              usuario["password_hash"]):
        log("ERROR", "Login fallido", tenant_id=tenant_id, user_id=user_id)
        raise ErrorHttp(403, "Credenciales inválidas")
    expira = int(time.time()) + int(os.environ.get("TOKEN_MINUTOS", "60")) * 60
    token = str(uuid.uuid4())
    tabla("TABLA_TOKENS").put_item(Item={
        "token": token, "tenant_id": tenant_id, "user_id": user_id, "rol": usuario["rol"],
        "expires": _iso(expira), "expires_epoch": expira, "ttl": expira + 3600})  # ttl: DynamoDB lo borra solo
    log("INFO", "Login exitoso", tenant_id=tenant_id, user_id=user_id, rol=usuario["rol"])
    return respuesta(200, {"token": token, "expires": _iso(expira), "tenant_id": tenant_id,
                           "user_id": user_id, "rol": usuario["rol"], "nombre": usuario.get("nombre", user_id)})


@manejar
def validar(event):
    """fsm-<stage>-validar-token. Entrada: {"token": "..."} (otra Lambda) o header Authorization (API).
    Salida: {"statusCode": 200, "body": {"tenant_id", "user_id", "rol"}}"""
    token = event.get("token") or token_de_headers(event)
    return respuesta(200, resolver_token(token))
