"""Login y validación de token. `validar` es la Lambda fsm-<stage>-validar-token que invocan los 5 MS."""
import hashlib
import hmac
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

from src.comun import (ErrorHttp, cuerpo, log, manejar, normalizar_login, respuesta, tabla,
                       token_de_headers)


def hash_password(password, salt_hex=None):
    """PBKDF2-SHA256 con salt. Retorna (salt_hex, hash_hex)."""
    salt = salt_hex or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000).hex()
    return salt, h


_SALT_FALSO = "00" * 16   # para gastar el mismo tiempo de CPU cuando el usuario no existe


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
    """POST /usuarios/login  {user_id, password} -> token con expiración.

    El tenant NO se envía: sale del usuario. `user_id` es único en todo el sistema (tabla logins).
    `tenant_id` se acepta por compatibilidad, pero si viene y no es el del usuario, falla igual
    que una contraseña incorrecta.
    """
    b = cuerpo(event)
    user_id, password = b.get("user_id") or b.get("usuario"), b.get("password")
    tenant_pedido = b.get("tenant_id")
    if not (isinstance(user_id, str) and isinstance(password, str) and user_id.strip() and password):
        raise ErrorHttp(400, "Se requiere user_id y password")
    login_id = normalizar_login(user_id)

    usuario = None
    entrada = tabla("TABLA_LOGINS").get_item(Key={"login": login_id}, ConsistentRead=True).get("Item")
    if entrada and (not tenant_pedido or tenant_pedido == entrada["tenant_id"]):
        usuario = tabla("TABLA_USUARIOS").get_item(
            Key={"tenant_id": entrada["tenant_id"], "user_id": login_id}).get("Item")

    if not usuario:
        hash_password(password, _SALT_FALSO)      # misma demora que un login con usuario real
        log("ERROR", "Login fallido", user_id=login_id)
        raise ErrorHttp(403, "Credenciales inválidas")
    if not hmac.compare_digest(hash_password(password, usuario["salt"])[1], usuario["password_hash"]):
        log("ERROR", "Login fallido", tenant_id=usuario["tenant_id"], user_id=login_id)
        raise ErrorHttp(403, "Credenciales inválidas")

    tenant_id = usuario["tenant_id"]
    expira = int(time.time()) + int(os.environ.get("TOKEN_MINUTOS", "60")) * 60
    token = str(uuid.uuid4())
    tabla("TABLA_TOKENS").put_item(Item={
        "token": token, "tenant_id": tenant_id, "user_id": login_id, "rol": usuario["rol"],
        "expires": _iso(expira), "expires_epoch": expira, "ttl": expira + 3600})  # ttl: DynamoDB lo borra solo
    log("INFO", "Login exitoso", tenant_id=tenant_id, user_id=login_id, rol=usuario["rol"])
    return respuesta(200, {"token": token, "expires": _iso(expira), "tenant_id": tenant_id,
                           "user_id": login_id, "rol": usuario["rol"], "nombre": usuario.get("nombre", login_id)})


@manejar
def validar(event):
    """fsm-<stage>-validar-token. Entrada: {"token": "..."} (otra Lambda) o header Authorization (API).
    Salida: {"statusCode": 200, "body": {"tenant_id", "user_id", "rol"}}"""
    token = event.get("token") or token_de_headers(event)
    return respuesta(200, resolver_token(token))
