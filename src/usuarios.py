"""Alta de usuarios. Solo un admin crea usuarios, y siempre dentro de SU tenant."""
import re

from botocore.exceptions import ClientError

from src.auth import hash_password, resolver_token
from src.comun import ROLES, ErrorHttp, ahora, cuerpo, log, manejar, respuesta, tabla, token_de_headers

_ID_VALIDO = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")


@manejar
def crear(event):
    """POST /usuarios  (Authorization de un admin)  {user_id, password, rol, nombre}"""
    admin = resolver_token(token_de_headers(event))
    if admin["rol"] != "admin":
        raise ErrorHttp(403, "Solo un admin puede crear usuarios")
    b = cuerpo(event)
    user_id, password = b.get("user_id"), b.get("password")
    rol, nombre = b.get("rol", "despachador"), b.get("nombre")
    if not isinstance(user_id, str) or not _ID_VALIDO.match(user_id):
        raise ErrorHttp(400, "user_id inválido (3 a 64 caracteres: letras, números, . _ @ -)")
    if not isinstance(password, str) or len(password) < 6:
        raise ErrorHttp(400, "El password debe tener al menos 6 caracteres")
    if rol not in ROLES:
        raise ErrorHttp(400, f"rol inválido. Opciones: {', '.join(ROLES)}")
    salt, hash_ = hash_password(password)
    item = {"tenant_id": admin["tenant_id"], "user_id": user_id, "rol": rol,
            "nombre": nombre if isinstance(nombre, str) and nombre.strip() else user_id,
            "salt": salt, "password_hash": hash_, "creado_en": ahora()}
    try:
        tabla("TABLA_USUARIOS").put_item(Item=item, ConditionExpression="attribute_not_exists(user_id)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise ErrorHttp(409, "El usuario ya existe en este tenant")
        raise
    log("INFO", "Usuario creado", tenant_id=admin["tenant_id"], user_id=user_id, rol=rol, creado_por=admin["user_id"])
    return respuesta(201, {"tenant_id": admin["tenant_id"], "user_id": user_id, "rol": rol, "nombre": item["nombre"]})
