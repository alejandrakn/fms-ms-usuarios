# MS-A · Autenticación (api-usuarios) — FSM SaaS

Login multi-tenant con token con expiración. Es el servicio del que dependen los otros 4 microservicios: cada Lambda invoca `fsm-<stage>-validar-token` antes de operar. **Se despliega primero.**

**Stack:** Python 3.12 · API Gateway (`integration: lambda`) · Lambda · DynamoDB · Serverless Framework v3 · Learner Lab (LabRole)

## Contrato con los demás microservicios

| | |
|---|---|
| Lambda | `fsm-<stage>-validar-token` |
| Entrada | `{"token": "..."}` |
| Salida OK | `{"statusCode": 200, "body": {"tenant_id": "tenant-1", "user_id": "admin1", "rol": "admin"}}` |
| Salida error | `{"statusCode": 403, "body": {"error": "Token expirado"}}` |
| Roles | `admin`, `despachador`, `tecnico` |
| Tenants | `tenant-1`, `tenant-2`, `tenant-3` |
| Header | `Authorization: Bearer <token>` |

Verificado contra el código real de `fsm-ms-visitas` (`validar_token`) y `fsm-ms-tecnicos` (`validarAcceso`, modo `shared`).

## Endpoints

| Método | Ruta | Qué hace | Quién |
|---|---|---|---|
| POST | `/usuarios/login` | Devuelve el token | público |
| POST | `/usuarios/validar` | Valida el token del header (útil para el frontend) | cualquiera con token |
| POST | `/usuarios` | Crea un usuario **en el tenant del admin** | solo `admin` |

Respuestas en formato de los talleres: `{"statusCode": ..., "body": ...}` (el HTTP siempre es 200; leer `statusCode`).

**Login** — `POST /usuarios/login`
```json
{ "tenant_id": "tenant-1", "user_id": "admin1", "password": "Fsm2026!" }
```
```json
{ "statusCode": 200, "body": { "token": "…", "expires": "2026-11-05T20:00:00Z", "tenant_id": "tenant-1", "user_id": "admin1", "rol": "admin", "nombre": "Admin Demo" } }
```
El frontend guarda `body.token` y lo manda en `Authorization: Bearer <token>`. El token dura 60 minutos (`TOKEN_MINUTOS`).

**Crear usuario** — `POST /usuarios` (header de un admin): `{"user_id": "desp2", "password": "Secreta1", "rol": "despachador", "nombre": "Ana"}`

## Datos (DynamoDB)

- `fsm-<stage>-usuarios`: PK `tenant_id` · SK `user_id` · `rol`, `nombre`, `salt`, `password_hash` (PBKDF2-SHA256), `creado_en`.
- `fsm-<stage>-tokens`: PK `token` · `tenant_id`, `user_id`, `rol`, `expires`, `expires_epoch`, `ttl` (DynamoDB borra los vencidos solos).

Estructura JSON completa en `docs/modelo-usuarios.json`.

## Desplegar

```bash
npm i -g serverless@3
sls deploy --stage dev
python3 scripts/poblar_usuarios.py --stage dev      # crea admin1 / despachador1 / tecnico1 en cada tenant
```
Password de demo: `Fsm2026!` (solo para datos ficticios; se cambia con `--password`). El script es la forma de crear el primer admin de cada tenant.

## Pruebas locales (AWS simulado)
```bash
pip install moto pytest boto3
pytest -q
```

## Logs (CloudWatch Logs Insights)
Formato `{"tipo": "INFO|ERROR", "mensaje": "...", "log_datos": {...}}`. Nunca se registran passwords ni tokens.
```
fields @timestamp, mensaje, log_datos.tenant_id, log_datos.user_id
| filter tipo = "ERROR"
| sort @timestamp desc
```
