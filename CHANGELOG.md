# Changelog
All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-27
### Added
- Full-value viewer mode `raw` for leaf values.
- Full-value viewer mode `base64` with automatic pretty-print when decoded payload is valid JSON.
- Full-value viewer mode `certificate` for X.509 certificates (PEM, base64 DER, and base64 PEM payloads).
- Keyboard switching between value views (`1`, `2`, `3`, `Tab`).

### Changed
- Main tree now preserves original JSON key order (no key sorting in object rendering).
- OpenSSL certificate text output now uses UTF-8 options (`-nameopt utf8`, UTF-8 decoding in subprocess output).

### Fixed
- Fixed certificate parsing for inputs encoded as `base64(PEM text)`.
- Improved certificate decode fallback behavior when OpenSSL is unavailable.

## [1.0.0] - 2026-02-06
### Added
- Initial stable release of secure TUI JSON/JSONL viewer.
- Lazy loading for large files, tree navigation, regex search, and field filtering.
- Security limits for JSON structure validation and safer file/path handling.

---

# История изменений
Все значимые изменения в проекте документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект следует [Semantic Versioning](https://semver.org/lang/ru/).

## [1.1.0] - 2026-02-27
### Добавлено
- Режим `raw` для просмотра значения листового узла.
- Режим декодирования `base64` с автоматическим pretty-print, если результат является валидным JSON.
- Режим декодирования сертификата X.509 (PEM, base64 DER и base64 PEM).
- Переключение режимов клавишами (`1`, `2`, `3`, `Tab`).

### Изменено
- На основном экране сохранен исходный порядок ключей JSON (сортировка ключей отключена).
- Вывод OpenSSL для сертификата переведен на UTF-8 (`-nameopt utf8`, декодирование вывода subprocess в UTF-8).

### Исправлено
- Исправлен разбор сертификатов в формате `base64(PEM text)`.
- Улучшен fallback-разбор сертификата, если OpenSSL недоступен.

## [1.0.0] - 2026-02-06
### Добавлено
- Первый стабильный релиз защищенного TUI-просмотрщика JSON/JSONL.
- Ленивый просмотр больших файлов, древовидная навигация, regex-поиск и фильтрация полей.
- Лимиты безопасности для валидации JSON-структуры и безопасной обработки путей/файлов.
