# WAF — Защита от форсированного веб-браузинга

Django-контейнер для обнаружения и блокировки атаки «форсированного веб-браузинга» (УБИ.159). Аналог модуля Wallarm Forced Browsing Protection.

## Run & Operate

- `cd artifacts/waf-container && python manage.py runserver 0.0.0.0:8000` — запустить WAF-сервер
- `cd artifacts/waf-container && python manage.py seed_demo` — загрузить демо-данные
- `cd artifacts/waf-container && python manage.py makemigrations waf && python manage.py migrate` — применить миграции
- `pnpm --filter @workspace/api-server run dev` — запустить Node.js API-сервер (порт 5000)
- `pnpm run typecheck` — полная проверка типов всех пакетов
- `pnpm run build` — сборка всех пакетов
- `pnpm --filter @workspace/api-spec run codegen` — перегенерировать API-хуки и Zod-схемы из OpenAPI spec
- `pnpm --filter @workspace/db run push` — применить изменения DB-схемы (только dev)
- Требуемые переменные окружения: `DATABASE_URL` — строка подключения к Postgres

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- **WAF: Django 4.2, Python 3.11, SQLite (хранение блокировок и событий)**
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/waf-container/` — Django WAF-проект
  - `waf/middleware.py` — основной middleware перехвата запросов
  - `waf/protection.py` — движок обнаружения атак (ProtectionEngine)
  - `waf/models.py` — модели: BlockedIP, SecurityEvent, RequestLog, TrustedIP
  - `waf/views.py` — API-эндпоинты и view-функции дашборда
  - `waf/templates/waf/dashboard.html` — HTML-дашборд с Chart.js
  - `config/waf_config.yaml` — конфигурация пороговых значений
  - `logs/security_events.json` — JSON-логи безопасности (ELK-совместимые)
- `lib/api-spec/openapi.yaml` — единый источник API-контракта
- `lib/api-client-react/` — сгенерированные React Query хуки
- `lib/api-zod/` — сгенерированные Zod-схемы

## Architecture decisions

- **Статичное хранение в SQLite**: для лабораторного проекта SQLite достаточно; production-вариант предполагает Redis для in-memory счётчиков
- **Скользящее окно (sliding window)**: подсчёт уникальных URL и 404-ответов в памяти (threading.Lock + deque), персистентность через Django ORM
- **Три режима работы**: `block` — блокировка + логирование, `monitoring` — только логирование, `disabled` — WAF отключён
- **Demo-режим без backend**: если `backend_url` пуст, запросы обрабатываются самим Django без проксирования
- **ELK-совместимые логи**: `waf/logger.py` пишет структурированный JSON в `logs/security_events.json`

## Product

WAF-контейнер перехватывает все входящие HTTP-запросы к защищаемому приложению и:
1. Считает уникальные URL per-IP в скользящем временном окне
2. Отслеживает долю ответов 404 и частоту запросов (RPS)
3. При превышении порогов автоматически блокирует IP с кодом 403
4. Логирует все события безопасности в JSON-формат (ELK-stack)
5. Предоставляет HTML-дашборд с графиками, таблицами событий, управлением блокировками

Dashboard доступен по `/waf/`, Django-admin по `/admin/` (логин: admin, пароль: admin123).

## User preferences

- Проект на Python/Django согласно ТЗ (УБИ.159 — форсированный веб-браузинг)
- Дашборд должен наглядно отображать количество заблокированных запросов и активных блокировок

## Gotchas

- Порт 8000 занят WAF Django Server — не запускать другие сервисы на этом порту
- После изменения моделей обязательно `makemigrations && migrate`
- Конфиг читается при старте `ProtectionEngine` — изменения в `waf_config.yaml` требуют перезапуска сервера
- При `backend_url = ""` в конфиге WAF работает в demo-режиме без реального проксирования

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
