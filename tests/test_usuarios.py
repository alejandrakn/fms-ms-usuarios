"""Pruebas locales con AWS simulado (moto). Correr: pip install moto pytest boto3 && pytest -q"""
import os
import time

import boto3
import pytest
from moto import mock_aws

os.environ.update(AWS_DEFAULT_REGION="us-east-1", AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="x",
                  TABLA_USUARIOS="fsm-test-usuarios", TABLA_TOKENS="fsm-test-tokens",
                  TABLA_LOGINS="fsm-test-logins", TOKEN_MINUTOS="60")


def _crear_tablas():
    d = boto3.client("dynamodb")
    d.create_table(TableName="fsm-test-usuarios", BillingMode="PAY_PER_REQUEST",
                   AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("tenant_id", "user_id")],
                   KeySchema=[{"AttributeName": "tenant_id", "KeyType": "HASH"},
                              {"AttributeName": "user_id", "KeyType": "RANGE"}])
    d.create_table(TableName="fsm-test-logins", BillingMode="PAY_PER_REQUEST",
                   AttributeDefinitions=[{"AttributeName": "login", "AttributeType": "S"}],
                   KeySchema=[{"AttributeName": "login", "KeyType": "HASH"}])
    d.create_table(TableName="fsm-test-tokens", BillingMode="PAY_PER_REQUEST",
                   AttributeDefinitions=[{"AttributeName": "token", "AttributeType": "S"}],
                   KeySchema=[{"AttributeName": "token", "KeyType": "HASH"}])


@pytest.fixture
def aws():
    with mock_aws():
        _crear_tablas()
        from src.usuarios import registrar
        # tenant-1 tiene admin1 y admin2; tenant-2 tiene admin3 y admin4: nombres únicos en todo el sistema
        for tenant, user, rol in [("tenant-1", "admin1", "admin"), ("tenant-1", "admin2", "admin"),
                                  ("tenant-1", "tec1", "tecnico"), ("tenant-2", "admin3", "admin"),
                                  ("tenant-2", "admin4", "admin")]:
            registrar(tenant, user, "Clave123", rol, user)
        yield


def ev(body=None, token=None):
    return {"body": body or {}, "headers": {"Authorization": f"Bearer {token}"} if token else {}}


def login(user, pw="Clave123", **extra):
    from src.auth import login as f
    return f(ev({"user_id": user, "password": pw, **extra}), None)


def test_login_sin_tenant_lo_deduce_del_usuario(aws):
    r = login("admin1")
    assert r["statusCode"] == 200
    b = r["body"]
    assert b["token"] and b["tenant_id"] == "tenant-1" and b["rol"] == "admin" and b["expires"]
    assert login("admin3")["body"]["tenant_id"] == "tenant-2"      # otro tenant, mismo formulario


def test_login_no_distingue_mayusculas_ni_espacios(aws):
    r = login("  ADMIN1 ")
    assert r["statusCode"] == 200 and r["body"]["user_id"] == "admin1"


def test_login_fallos_no_revelan_si_existe_el_usuario(aws):
    assert login("admin1", pw="mala")["statusCode"] == 403
    r = login("fantasma")
    assert r["statusCode"] == 403 and r["body"]["error"] == "Credenciales inválidas"
    assert login("admin1", pw="")["statusCode"] == 400
    assert login("", pw="x")["statusCode"] == 400


def test_login_tenant_opcional_si_viene_debe_coincidir(aws):
    assert login("admin1", tenant_id="tenant-1")["statusCode"] == 200
    r = login("admin1", tenant_id="tenant-2")                     # compatibilidad: si lo mandan, no puede mentir
    assert r["statusCode"] == 403 and r["body"]["error"] == "Credenciales inválidas"


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
    # el empleado nuevo entra solo con su usuario y clave, y cae en el tenant de quien lo creó
    r = login("desp9", pw="Secreta1")
    assert r["statusCode"] == 200 and r["body"]["tenant_id"] == "tenant-1" and r["body"]["rol"] == "despachador"


def test_nombre_de_usuario_es_unico_en_todo_el_sistema(aws):
    from src.usuarios import crear
    adm1 = login("admin1")["body"]["token"]
    msg = "Ese nombre de usuario ya está en uso"
    # duplicado en el mismo tenant
    r = crear(ev({"user_id": "tec1", "password": "Secreta1", "rol": "tecnico"}, adm1), None)
    assert r["statusCode"] == 409 and r["body"]["error"] == msg
    # nombre que ya usa otro tenant (admin3 es de tenant-2): se rechaza con el mismo mensaje
    r = crear(ev({"user_id": "admin3", "password": "Secreta1", "rol": "admin"}, adm1), None)
    assert r["statusCode"] == 409 and r["body"]["error"] == msg
    # y no se pisó la cuenta del otro tenant
    assert login("admin3")["body"]["tenant_id"] == "tenant-2"
    # mayúsculas cuentan como el mismo nombre
    r = crear(ev({"user_id": "ADMIN3", "password": "Secreta1", "rol": "admin"}, adm1), None)
    assert r["statusCode"] == 409


def test_alta_es_atomica_no_deja_login_huerfano(aws):
    from src.usuarios import crear
    adm = login("admin1")["body"]["token"]
    crear(ev({"user_id": "tec1", "password": "Secreta1", "rol": "tecnico"}, adm), None)   # falla: ya existe
    logins = boto3.resource("dynamodb").Table("fsm-test-logins").scan()["Items"]
    assert sorted(i["login"] for i in logins) == ["admin1", "admin2", "admin3", "admin4", "tec1"]


def test_crear_usuario_guarda_en_minusculas(aws):
    from src.usuarios import crear
    adm = login("admin1")["body"]["token"]
    r = crear(ev({"user_id": "Maria.Lopez", "password": "Secreta1", "rol": "tecnico"}, adm), None)
    assert r["statusCode"] == 201 and r["body"]["user_id"] == "maria.lopez"
    assert login("MARIA.LOPEZ", pw="Secreta1")["statusCode"] == 200


def test_crear_usuario_valida_datos(aws):
    from src.usuarios import crear
    adm = login("admin1")["body"]["token"]
    assert crear(ev({"user_id": "x", "password": "Secreta1"}, adm), None)["statusCode"] == 400
    assert crear(ev({"user_id": "ok_user", "password": "123"}, adm), None)["statusCode"] == 400
    assert crear(ev({"user_id": "ok_user", "password": "Secreta1", "rol": "dios"}, adm), None)["statusCode"] == 400
    assert crear(ev({"user_id": "con espacio", "password": "Secreta1"}, adm), None)["statusCode"] == 400
