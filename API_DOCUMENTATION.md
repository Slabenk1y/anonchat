# API — текущий и планируемый

## Текущие HTTP endpoints
- `GET /`: отдаёт `index.html`.
- `GET /healthz`: health check.
- `GET /api/online`: количество активных WebSocket-сессий; это не число зарегистрированных пользователей.

## Текущий WebSocket
- Endpoint: `/ws`.
- Клиентские команды передаются текстовыми кадрами, поля разделяются табуляцией.
- Поддерживаемые команды в коде: `ping`, `find`, `random`, `msg`, `typing`, `leave`, `report`.
- Серверные события включают `hb`, `err`, `waiting`, `matched`, `msg`, `typing`, `left`, `banned`.
- Текущий протокол не является версионированным публичным API.

## Планируемые API
Auth, profile, matching, chat и moderation endpoints будут описаны здесь после реализации и тестирования. Не считать планируемые маршруты работающими.
