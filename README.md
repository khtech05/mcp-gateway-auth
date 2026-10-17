# mcp-gateway-auth

Проверка «внутреннего пропуска» MCP-шлюза KH Tech — всё, что нужно MCP-серверу от авторизации.

Сервер за шлюзом не занимается входом сотрудников: шлюз уже разобрался, кто пришёл и есть ли у него
доступ, и приложил к запросу короткоживущий токен со сведениями о сотруднике. Эта библиотека
проверяет такой токен и говорит, кто за запросом. Писать проверку самому не нужно.

## Установка

```
uv add "mcp-gateway-auth[fastmcp] @ git+https://github.com/khtech05/mcp-gateway-auth@v0.1.0"
```

Без FastMCP — то же без `[fastmcp]`. Нужен Python 3.11+.

## Как пользоваться

```python
from fastmcp import FastMCP
from mcp_gateway_auth import current_principal
from mcp_gateway_auth.fastmcp import GatewayAuth

mcp = FastMCP("crm", auth=GatewayAuth(audience="crm"))  # audience — короткое имя вашего сервера


@mcp.tool
def find_deal(query: str) -> str:
    user = current_principal()
    user.sub  # постоянный id сотрудника — используйте как ключ
    user.name  # «Алиса Иванова», для показа
    user.has_role("mcp-crm")
    user.in_group("/Продажи")  # сама группа или любая её подгруппа
    ...


mcp.run(transport="http", host="0.0.0.0", port=8000, path="/mcp")
```

Для любого ASGI-приложения есть `GatewayAuthMiddleware(app, audience="crm")`, без фреймворка —
`verify(token, audience="crm")`. Отказы — исключения от `AuthError`: `MissingToken`,
`InvalidToken` (`TokenExpired`, `InvalidAudience`, `InvalidIssuer`, `UnknownKey`),
`JWKSUnavailable`.

## Что именно проверяется

Подпись Ed25519 ключом шлюза, `iss = mcp-gateway`, `aud` строго равен вашему `audience` (токен
для другого сервера не принимается), `exp`/`iat` с допуском 10 секунд, непустой `sub`.

Открытые ключи берутся по адресу из `MCP_GATEWAY_JWKS_URL` (по умолчанию
`http://mcp-gateway:9000/jwks.json` — он доступен только во внутренней docker-сети между шлюзом и
вашим сервером). Ключи кэшируются на 10 минут, при незнакомом ключе перечитываются, а если шлюз
недоступен — работа продолжается на кэше. Ротацию ключей на стороне шлюза библиотека переживает
сама, делать ничего не нужно.

## Как это связано со шлюзом

Библиотека живёт здесь и выпускается своими версиями (теги `vX.Y.Z`) — независимо от выкладок
шлюза. Сам контракт пропуска задаёт шлюз, его описание — в `docs/internal-jwt.md` репозитория
шлюза; там же, в `docs/onboarding.md`, чеклист подключения нового сервера.

Тесты здесь проверяют только нашу половину контракта: пропуска им выпускает маленький двойник
шлюза (`tests/conftest.py`), настоящий код шлюза для этого не нужен. Что выпуск и проверка сходятся
по-настоящему, проверяет сквозной тест в репозитории шлюза: он поднимает шлюз и demo-сервер с этой
библиотекой и прогоняет запрос насквозь. Поэтому шлюз держит её у себя в dev-зависимостях — в его
рабочий код она не входит.

## Разработка

```
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
```
