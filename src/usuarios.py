"""Alta de usuarios. Solo un admin crea usuarios, y siempre dentro de SU tenant.

El nombre de usuario (user_id) es único en TODO el sistema: así el login no necesita el tenant.
Se garantiza con la tabla `logins` y una transacción (usuario + login se crean juntos o ninguno).
"""
import re

from botocore.exceptions import ClientError

from src.auth import hash_password, resolver_token
from src.comun import (ROLES, ErrorHttp, ahora, cuerpo, log, manejar, normalizar_login, respuesta,
                       tabla, token_de_headers)

_ID_VALIDO = re.compile(r"^[a-z0-9_.@-]{3,64}$")


def registrar(tenant_id, user_id, password, rol, nombre=None, creado_por=None):
    """Crea el usuario y reserva su nombre en toda la plataforma. Devuelve el item guardado.

    Lanza ErrorHttp 400 si los datos no son válidos y 409 si el nombre ya está en uso (en cualquier tenant).
    """
    user_id = normalizar_login(user_id)
    if not _ID_VALIDO.match(user_id):
        raise ErrorHttp(400, "user_id inválido (3 a 64 caracteres: letras, números, . _ @ -)")
    if not isinstance(password, str) or len(password) < 6:
        raise ErrorHttp(400, "El password debe tener al menos 6 caracteres")
    if rol not in ROLES:
        raise ErrorHttp(400, f"rol inválido. Opciones: {', '.join(ROLES)}")

    salt, hash_ = hash_password(password)
    item = {"tenant_id": tenant_id, "user_id": user_id, "rol": rol,
            "nombre": nombre.strip() if isinstance(nombre, str) and nombre.strip() else user_id,
            "salt": salt, "password_hash": hash_, "creado_en": ahora()}
    if creado_por:
        item["creado_por"] = creado_por
    cliente = tabla("TABLA_USUARIOS").meta.client
    try:
        cliente.transact_write_items(TransactItems=[
            {"Put": {"TableName": tabla("TABLA_LOGINS").name,
                     "Item": {"login": user_id, "tenant_id": tenant_id},
                     "ConditionExpression": "attribute_not_exists(login)"}},
            {"Put": {"TableName": tabla("TABLA_USUARIOS").name, "Item": item,
                     "ConditionExpression": "attribute_not_exists(user_id)"}},
        ])
    except ClientError as e:
        if e.response["Error"]["Code"] == "TransactionCanceledException":
            raise ErrorHttp(409, "Ese nombre de usuario ya está en uso")
        raise
    return item


@manejar
def crear(event):
    """POST /usuarios  (Authorization de un admin)  {user_id, password, rol, nombre}"""
    admin = resolver_token(token_de_headers(event))
    if admin["rol"] != "admin":
        raise ErrorHttp(403, "Solo un admin puede crear usuarios")
    b = cuerpo(event)
    item = registrar(admin["tenant_id"], b.get("user_id"), b.get("password"),
                     b.get("rol", "despachador"), b.get("nombre"), creado_por=admin["user_id"])
    log("INFO", "Usuario creado", tenant_id=admin["tenant_id"], user_id=item["user_id"],
        rol=item["rol"], creado_por=admin["user_id"])
    return respuesta(201, {"tenant_id": item["tenant_id"], "user_id": item["user_id"],
                           "rol": item["rol"], "nombre": item["nombre"]})
