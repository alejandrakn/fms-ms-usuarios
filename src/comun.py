"""Utilidades de MS-A (api-usuarios). Mismo estilo que MS-D (Visitas): respuesta {"statusCode", "body"}."""
import json
import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3

_dynamodb = boto3.resource("dynamodb")

ROLES = ("admin", "despachador", "tecnico")


class ErrorHttp(Exception):
    def __init__(self, status, mensaje):
        super().__init__(mensaje)
        self.status = status
        self.mensaje = mensaje


def tabla(variable_entorno):
    return _dynamodb.Table(os.environ[variable_entorno])


def normalizar_login(valor):
    """El nombre de usuario no distingue mayúsculas ni espacios en los bordes."""
    return valor.strip().lower() if isinstance(valor, str) else ""


def ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def a_json(obj):
    """Convierte Decimal (DynamoDB) a int/float para devolverlo en la respuesta."""
    if isinstance(obj, list):
        return [a_json(x) for x in obj]
    if isinstance(obj, dict):
        return {k: a_json(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    return obj


def respuesta(status, body):
    # integration: lambda -> API Gateway devuelve este objeto tal cual (mismo formato que los talleres)
    return {"statusCode": status, "body": a_json(body)}


def log(tipo, mensaje, **datos):
    """Log JSON para CloudWatch Logs Insights (tipo = INFO / ERROR). Nunca registrar passwords ni tokens."""
    print(json.dumps({"tipo": tipo, "mensaje": mensaje, "log_datos": datos}, default=str))


def cuerpo(event):
    b = event.get("body") or {}
    try:
        b = json.loads(b) if isinstance(b, str) else b
    except json.JSONDecodeError:
        raise ErrorHttp(400, "El cuerpo no contiene un JSON válido")
    if not isinstance(b, dict):
        raise ErrorHttp(400, "El cuerpo debe ser un objeto JSON")
    return b


def token_de_headers(event):
    headers = event.get("headers") or {}
    for clave, valor in headers.items():
        if clave.lower() == "authorization" and valor:
            valor = valor.strip()
            return valor[7:].strip() if valor.lower().startswith("bearer ") else valor
    return None


def manejar(funcion):
    """Convierte errores en respuestas y registra los fallos inesperados."""
    def envoltura(event, context):
        try:
            return funcion(event)
        except ErrorHttp as e:
            return respuesta(e.status, {"error": e.mensaje})
        except Exception as e:  # noqa: BLE001
            log("ERROR", f"Error en {funcion.__name__}", error=repr(e))
            return respuesta(500, {"error": "Error interno"})
    return envoltura
