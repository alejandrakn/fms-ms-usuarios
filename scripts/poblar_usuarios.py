"""Crea los usuarios de demo de cada tenant. Los nombres de usuario son únicos en todo el sistema.

Por cada tenant (según su posición en --tenants) crea 3 admins, 1 despachador y 1 técnico:
    tenant-1: admin1, admin2, admin3, despachador1, tecnico1
    tenant-2: admin4, admin5, admin6, despachador2, tecnico2
    tenant-3: admin7, admin8, admin9, despachador3, tecnico3

Uso (con las credenciales del Learner Lab en ~/.aws/credentials):
    python3 scripts/poblar_usuarios.py --stage dev
    python3 scripts/poblar_usuarios.py --stage dev --limpiar        # borra TODOS los usuarios, logins y tokens antes
    python3 scripts/poblar_usuarios.py --stage dev --password 'OtraClave1'

Es la forma de crear los PRIMEROS admins de cada tenant (POST /usuarios exige un admin autenticado).
La clave de demo es solo para pruebas con datos ficticios. Se puede repetir sin problema: los usuarios
que ya existen en su tenant se omiten. Si un nombre ya pertenece a OTRO tenant (por ejemplo, usuarios de
una versión anterior, donde admin1 existía en los 3), se aborta y hay que usar --limpiar.
"""
import argparse
import os
import sys

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import boto3  # noqa: E402

ADMINS_POR_TENANT = 3


def usuarios_de(indice):
    """Usuarios del tenant número `indice` (0, 1, 2...): [(user_id, rol, nombre)]."""
    lista = [(f"admin{indice * ADMINS_POR_TENANT + k}", "admin", f"Admin {indice * ADMINS_POR_TENANT + k}")
             for k in range(1, ADMINS_POR_TENANT + 1)]
    lista.append((f"despachador{indice + 1}", "despachador", f"Despachador {indice + 1}"))
    lista.append((f"tecnico{indice + 1}", "tecnico", f"Técnico {indice + 1}"))
    return lista


def vaciar(tabla, claves):
    """Borra todos los items de una tabla (solo para datos de demo)."""
    total = 0
    r = tabla.scan(ProjectionExpression=", ".join(f"#{c}" for c in claves),
                   ExpressionAttributeNames={f"#{c}": c for c in claves})
    while True:
        with tabla.batch_writer() as bw:
            for item in r["Items"]:
                bw.delete_item(Key={c: item[c] for c in claves})
                total += 1
        if "LastEvaluatedKey" not in r:
            return total
        r = tabla.scan(ExclusiveStartKey=r["LastEvaluatedKey"],
                       ProjectionExpression=", ".join(f"#{c}" for c in claves),
                       ExpressionAttributeNames={f"#{c}": c for c in claves})


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--stage", default="dev")
    p.add_argument("--tenants", default="tenant-1,tenant-2,tenant-3")
    p.add_argument("--password", default="Fsm2026!")
    p.add_argument("--limpiar", action="store_true",
                   help="borra todos los usuarios, logins y tokens del stage antes de crear")
    a = p.parse_args()

    os.environ["TABLA_USUARIOS"] = f"fsm-{a.stage}-usuarios"
    os.environ["TABLA_LOGINS"] = f"fsm-{a.stage}-logins"
    os.environ["TABLA_TOKENS"] = f"fsm-{a.stage}-tokens"
    from src.comun import ErrorHttp, tabla                     # noqa: E402  (después de fijar las tablas)
    from src.usuarios import registrar                         # noqa: E402

    if a.limpiar:
        n_u = vaciar(tabla("TABLA_USUARIOS"), ("tenant_id", "user_id"))
        n_l = vaciar(tabla("TABLA_LOGINS"), ("login",))
        n_t = vaciar(tabla("TABLA_TOKENS"), ("token",))
        print(f"Limpieza: {n_u} usuarios, {n_l} logins, {n_t} tokens borrados")

    for i, tenant in enumerate(t.strip() for t in a.tenants.split(",") if t.strip()):
        creados = []
        for user_id, rol, nombre in usuarios_de(i):
            dueno = tabla("TABLA_LOGINS").get_item(Key={"login": user_id}, ConsistentRead=True).get("Item")
            if dueno and dueno["tenant_id"] != tenant:
                sys.exit(f"'{user_id}' ya pertenece a {dueno['tenant_id']}. Corre de nuevo con --limpiar.")
            if dueno:
                continue                                       # ya existía en este tenant
            try:
                registrar(tenant, user_id, a.password, rol, nombre, creado_por="seed")
            except ErrorHttp as e:
                if e.status == 409:   # el nombre existe en la tabla de usuarios pero no en logins: datos de la versión anterior
                    sys.exit(f"'{user_id}' ya existe de una versión anterior (sin registro de login). "
                             "Corre de nuevo con --limpiar.")
                sys.exit(f"No se pudo crear {user_id}: {e.mensaje}")
            creados.append(user_id)
        print(f"[{tenant}] creados: {', '.join(creados) or 'ninguno (ya existían)'}")
    print(f"Listo. Password de demo: {a.password}")


if __name__ == "__main__":
    main()
