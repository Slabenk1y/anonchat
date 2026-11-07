# DATABASE_SCHEMA — проектная схема

Миграция `migrations/0001_accounts_and_safety.sql` теперь задаёт начальную PostgreSQL-схему аккаунтов, хешированных сессий, профилей, настроек, блокировок и жалоб. Она ещё не подключена к серверу и не применена к работающей базе данных.

## Предлагаемые таблицы
- `users`: id (UUID), username, password_hash, created_at, status.
- `sessions`: id, user_id, token_hash, created_at, expires_at, revoked_at.
- `profiles`: user_id, avatar_key, locale, created_at, updated_at.
- `user_settings`: user_id, theme_key, sound_enabled, compact_mode, preferences_json.
- `blocks`: id, blocker_user_id, blocked_user_id, created_at.
- `reports`: id, reporter_user_id, reported_user_id, category, limited_context, status, created_at, reviewed_at.
- `moderation_actions`: id, user_id, action, reason_code, starts_at, ends_at, created_at.
- `entitlements`: id, user_id, entitlement_key, source, starts_at, ends_at.
- `wallets` и `wallet_transactions`: только на этапе экономики; баланс изменяется транзакционно, журнал неизменяем.
- `owned_items`: только на этапе магазина.

## Правила
- Пароли не хранятся открытым текстом.
- Сессионные секреты в базе хранятся только в виде криптографического хеша.
- Уникальные индексы для username в нормализованном виде и token_hash.
- Внешние ключи и транзакции для связанных операций.
- Не хранить точную дату рождения, если возрастную проверку можно выполнить без неё; минимизировать персональные данные.
- Не хранить содержимое случайных чатов постоянно по умолчанию.
- Любая таблица с пользовательскими данными должна иметь план удаления и retention.
