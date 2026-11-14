# MS-A · Autenticación (api-usuarios) — FSM SaaS

Login con token con expiración. **El usuario no elige empresa: entra con su usuario y contraseña y el sistema deduce su tenant.** Es el servicio del que dependen los otros 4 microservicios: cada Lambda invoca `fsm-<stage>-validar-token` antes de operar. **Se despliega primero.**

**Stack:** Python 3.12 · API Gateway (`integration: lambda`) · Lambda · DynamoDB · Serverless Framework v3 · Learner Lab (LabRole)

## Contrato con los demás microservicios

| | |
|---|---|
| Lambda | `fsm-<stage>-validar-token` |
| Entrada | `{"token": "..."}` |
| Salida OK | `{"statusCode": 200, "body": {"tenant_id": "tenant-1", "user_id": "admin1", "rol": "admin"}}` |
| Salida error | `{"statusCode": 403, "body": {"error": "Token expirado"}}` |
| Roles | `admin`, `despachador`, `tecnico` |
| Tenants | `tenant-1`, `tenant-2`, `tenant-3` (se deducen del usuario; no se envían al hacer login) |
| Header | `Authorization: Bearer <token>` |

Verificado contra el código real de `fsm-ms-visitas` (`validar_token`) y `fsm-ms-tecnicos` (`validarAcceso`, modo `shared`).

## Endpoints

| Método | Ruta | Qué hace | Quién |
|---|---|---|---|
| POST | `/usuarios/login` | Devuelve el token | público |
| POST | `/usuarios/validar` | Valida el token del header (útil para el frontend) | cualquiera con token |
| POST | `/usuarios` | Crea un usuario **en el tenant del admin** | solo `admin` |

Respuestas en formato de los talleres: `{"statusCode": ..., "body": ...}` (el HTTP siempre es 200; leer `statusCode`).

**Login** — `POST /usuarios/login` (sin tenant)
```json
{ "user_id": "admin1", "password": "Fsm2026!" }
```
`user_id` es **único en todo el sistema** y no distingue mayúsculas (`Admin1` = `admin1`). La respuesta trae el `tenant_id` del usuario. Por compatibilidad se acepta un `tenant_id` opcional, pero si viene y no es el del usuario el login falla como una clave incorrecta.
```json
{ "statusCode": 200, "body": { "token": "…", "expires": "2026-11-05T20:00:00Z", "tenant_id": "tenant-1", "user_id": "admin1", "rol": "admin", "nombre": "Admin Demo" } }
```
El frontend guarda `body.token` y lo manda en `Authorization: Bearer <token>`. El token dura 60 minutos (`TOKEN_MINUTOS`).

**Crear usuario** — `POST /usuarios` (header de un admin): `{"user_id": "ana.perez", "password": "Secreta1", "rol": "despachador", "nombre": "Ana"}`
El usuario queda siempre en el tenant del admin que lo crea y entra solo con su usuario y clave. Si el nombre ya existe (en este u otro tenant) responde `409 "Ese nombre de usuario ya está en uso"`. El alta es atómica (usuario + login en una transacción).

## Datos (DynamoDB)

- `fsm-<stage>-usuarios`: PK `tenant_id` · SK `user_id` · `rol`, `nombre`, `salt`, `password_hash` (PBKDF2-SHA256), `creado_en`.
- `fsm-<stage>-logins`: PK `login` (el user_id en minúsculas) · `tenant_id`. Hace único el nombre de usuario en todo el sistema y permite el login sin tenant.
- `fsm-<stage>-tokens`: PK `token` · `tenant_id`, `user_id`, `rol`, `expires`, `expires_epoch`, `ttl` (DynamoDB borra los vencidos solos).

Estructura JSON completa en `docs/modelo-usuarios.json`.

## Desplegar

```bash
npm i -g serverless@3
sls deploy --stage dev
python3 scripts/poblar_usuarios.py --stage dev --limpiar   # --limpiar borra los usuarios, logins y tokens anteriores
```
Usuarios de demo (clave `Fsm2026!`, se cambia con `--password`), únicos en todo el sistema:

| Tenant | Admins | Despachador | Técnico |
|---|---|---|---|
| tenant-1 | admin1, admin2, admin3 | despachador1 | tecnico1 |
| tenant-2 | admin4, admin5, admin6 | despachador2 | tecnico2 |
| tenant-3 | admin7, admin8, admin9 | despachador3 | tecnico3 |

> **Al actualizar desde la versión anterior** (donde `admin1` existía en los 3 tenants) hay que usar `--limpiar` una vez. Los tokens emitidos antes dejan de servir.

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
