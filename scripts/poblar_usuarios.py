"""Crea los usuarios de demo en cada tenant (admin1, despachador1, tecnico1).

Uso (con las credenciales del Learner Lab en ~/.aws/credentials):
    python3 scripts/poblar_usuarios.py --stage dev
    python3 scripts/poblar_usuarios.py --stage dev --tenants tenant-1,tenant-2,tenant-3 --password 'OtraClave1'

Es la forma de crear el PRIMER admin de cada tenant (POST /usuarios exige un admin autenticado).
La clave de demo es solo para pruebas con datos ficticios.
"""
import argparse
import os
import sys

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import boto3  # noqa: E402

from src.auth import hash_password  # noqa: E402

USUARIOS = [("admin1", "admin", "Admin Demo"),
            ("despachador1", "despachador", "Despachador Demo"),
            ("tecnico1", "tecnico", "Técnico Demo")]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--stage", default="dev")
    p.add_argument("--tenants", default="tenant-1,tenant-2,tenant-3")
    p.add_argument("--password", default="Fsm2026!")
    a = p.parse_args()
    tabla = boto3.resource("dynamodb").Table(f"fsm-{a.stage}-usuarios")
    for tenant in a.tenants.split(","):
        for user_id, rol, nombre in USUARIOS:
            salt, h = hash_password(a.password)
            tabla.put_item(Item={"tenant_id": tenant, "user_id": user_id, "rol": rol, "nombre": nombre,
                                 "salt": salt, "password_hash": h, "creado_en": "2026-11-01T00:00:00Z"})
        print(f"[{tenant}] usuarios: " + ", ".join(u for u, _, _ in USUARIOS))
    print(f"Listo. Password de demo: {a.password}")


if __name__ == "__main__":
    main()
