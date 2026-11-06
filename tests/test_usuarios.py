"""Pruebas locales con AWS simulado (moto). Correr: pip install moto pytest boto3 && pytest -q"""
import os
import time

import boto3
import pytest
from moto import mock_aws

os.environ.update(AWS_DEFAULT_REGION="us-east-1", AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="x",
                  TABLA_USUARIOS="fsm-test-usuarios", TABLA_TOKENS="fsm-test-tokens", TOKEN_MINUTOS="60")


@pytest.fixture
def aws():
    with mock_aws():
        d = boto3.client("dynamodb")
        d.create_table(TableName="fsm-test-usuarios", BillingMode="PAY_PER_REQUEST",
                       AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("tenant_id", "user_id")],
                       KeySchema=[{"AttributeName": "tenant_id", "KeyType": "HASH"},
                                  {"AttributeName": "user_id", "KeyType": "RANGE"}])
        d.create_table(TableName="fsm-test-tokens", BillingMode="PAY_PER_REQUEST",
                       AttributeDefinitions=[{"AttributeName": "token", "AttributeType": "S"}],
                       KeySchema=[{"AttributeName": "token", "KeyType": "HASH"}])
        from src.auth import hash_password
        t = boto3.resource("dynamodb").Table("fsm-test-usuarios")
        for tenant, user, rol in [("tenant-1", "admin1", "admin"), ("tenant-1", "tec1", "tecnico"),
                                  ("tenant-2", "admin2", "admin")]:
            salt, h = hash_password("Clave123")
            t.put_item(Item={"tenant_id": tenant, "user_id": user, "rol": rol, "nombre": user,
                             "salt": salt, "password_hash": h})
        yield


def ev(body=None, token=None):
    return {"body": body or {}, "headers": {"Authorization": f"Bearer {token}"} if token else {}}


def login(user, tenant="tenant-1", pw="Clave123"):
    from src.auth import login as f
    return f(ev({"tenant_id": tenant, "user_id": user, "password": pw}), None)


def test_login_ok_devuelve_token_y_datos(aws):
    r = login("admin1")
    assert r["statusCode"] == 200
    b = r["body"]
    assert b["token"] and b["tenant_id"] == "tenant-1" and b["rol"] == "admin" and b["expires"]


def test_login_fallos_no_revelan_si_existe_el_usuario(aws):
    assert login("admin1", pw="mala")["statusCode"] == 403
    r = login("fantasma")
    assert r["statusCode"] == 403 and r["body"]["error"] == "Credenciales inválidas"
    assert login("admin1", tenant="tenant-2")["statusCode"] == 403   # mismo user_id, otro tenant
    assert login("admin1", pw="")["statusCode"] == 400


def test_validar_contrato_body_es_objeto_con_tenant_y_rol(aws):
    from src.auth import validar
    tok = login("tec1")["body"]["token"]
    r = validar({"token": tok}, None)               # como lo invocan los otros MS
    assert r == {"statusCode": 200, "body": {"tenant_id": "tenant-1", "user_id": "tec1", "rol": "tecnico"}}
    r2 = validar(ev(token=tok), None)               # como lo llama el frontend
    assert r2["statusCode"] == 200 and r2["body"]["rol"] == "tecnico"


def test_validar_rechaza_token_falso_vacio_y_expirado(aws):
    from src.auth import validar
    assert validar({"token": "inventado"}, None)["statusCode"] == 403
    assert validar({}, None)["statusCode"] == 403
    tok = login("admin1")["body"]["token"]
    boto3.resource("dynamodb").Table("fsm-test-tokens").update_item(
        Key={"token": tok}, UpdateExpression="SET expires_epoch = :e",
        ExpressionAttributeValues={":e": int(time.time()) - 5})
    r = validar({"token": tok}, None)
    assert r["statusCode"] == 403 and "expirado" in r["body"]["error"]


def test_crear_usuario_solo_admin_y_en_su_tenant(aws):
    from src.usuarios import crear
    adm = login("admin1")["body"]["token"]
    tec = login("tec1")["body"]["token"]
    nuevo = {"user_id": "desp9", "password": "Secreta1", "rol": "despachador", "tenant_id": "tenant-2"}
    assert crear(ev(nuevo, tec), None)["statusCode"] == 403          # un técnico no puede
    assert crear(ev(nuevo), None)["statusCode"] == 403               # sin token
    r = crear(ev(nuevo, adm), None)
    assert r["statusCode"] == 201 and r["body"]["tenant_id"] == "tenant-1"   # ignora el tenant del body
    assert login("desp9", tenant="tenant-1", pw="Secreta1")["statusCode"] == 200
    assert login("desp9", tenant="tenant-2", pw="Secreta1")["statusCode"] == 403
    assert crear(ev(nuevo, adm), None)["statusCode"] == 409           # duplicado


def test_crear_usuario_valida_datos(aws):
    from src.usuarios import crear
    adm = login("admin1")["body"]["token"]
    assert crear(ev({"user_id": "x", "password": "Secreta1"}, adm), None)["statusCode"] == 400
    assert crear(ev({"user_id": "ok_user", "password": "123"}, adm), None)["statusCode"] == 400
    assert crear(ev({"user_id": "ok_user", "password": "Secreta1", "rol": "dios"}, adm), None)["statusCode"] == 400
