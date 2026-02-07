#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TUI JSON viewer - интерактивный просмотрщик JSON/JSONL файлов.
SECURE VERSION с защитой от DoS атак.

Защиты:
- Проверка каждого объекта на JSON Bomb (глубина, размер строк, длина чисел)
- Защита от устройств (/dev/zero, /dev/random)
- Timeout для regex (2 секунды)
- Ограничение expand_all (100K узлов)
- Валидация JSON структуры при загрузке

Возможности:
- Ленивая загрузка больших файлов (миллионы объектов)
- Древовидная навигация с разворачиванием/сворачиванием узлов
- Поиск по полям с regex
- Фильтрация отображаемых полей
- Просмотр полных значений длинных полей
- Переход между объектами с сохранением позиции

Управление:
  ↑↓ / j k      - навигация по узлам
  →← / l        - развернуть/свернуть узел
  Enter         - просмотр полного значения (для листовых узлов)
  a / z         - развернуть/свернуть текущий объект
  A / Z         - развернуть/свернуть ВСЕ объекты
  s             - поиск по текущему полю
  F             - глобальный поиск по всем полям с авто-фильтром
  f             - выбор полей для фильтрации
  n / p         - следующий/предыдущий результат поиска
  g             - переход к объекту по номеру
  Home / End    - первый/последний объект
  PgUp / PgDn   - предыдущий/следующий объект (с сохранением позиции)
  q / Esc       - выход
"""

import sys
import json
import os
import curses
import re
import signal
from typing import List, Optional, Tuple, Set, Any
from pathlib import Path

__version__ = "1.0.0"
__author__ = "Tarasov Dmitry"

# ===== SECURITY CONFIGURATION =====
MAX_JSON_DEPTH = 100                # Максимальная вложенность JSON
MAX_STRING_LENGTH = 10 * 1024 * 1024  # 10 MB на одну строку
MAX_NUMBER_DIGITS = 4300            # CVE-2020-10735 (Python 3.11+ имеет защиту)
MAX_ARRAY_ITEMS = 1000000           # Максимум элементов в массиве
MAX_OBJECT_KEYS = 100000            # Максимум ключей в объекте
MAX_EXPAND_NODES = 100000           # Максимум узлов при expand_all
REGEX_TIMEOUT = 2                   # Секунды - защита от ReDoS
FORBIDDEN_DEVICES = ['/dev/', '/proc/', '/sys/']  # Защита от чтения устройств


class SecurityError(Exception):
    """Исключение для ошибок безопасности."""
    pass


class TimeoutError(Exception):
    """Исключение при превышении времени выполнения."""
    pass


def validate_file_path(filepath: str) -> Path:
    """
    Валидация пути к файлу с проверками безопасности.

    Проверки:
    1. Файл существует
    2. Это обычный файл (не директория, не устройство)
    3. Не является устройством (/dev/zero, /proc, etc)

    Raises:
        SecurityError: При обнаружении небезопасного пути
        ValueError: При невалидном пути
    """
    try:
        path = Path(filepath).resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Невалидный путь: {e}")

    # Проверка существования
    if not path.exists():
        raise ValueError(f"Файл не найден: {filepath}")

    # Проверка что это обычный файл
    if not path.is_file():
        raise SecurityError(f"Путь не является обычным файлом: {filepath}")

    # SECURITY: Проверка на устройства
    path_str = str(path)
    for forbidden in FORBIDDEN_DEVICES:
        if path_str.startswith(forbidden):
            raise SecurityError(f"Доступ к устройствам запрещен: {path_str}")

    return path


def validate_json_object(obj: Any, depth: int = 0, path: str = "root") -> None:
    """
    Рекурсивная валидация JSON объекта на опасные структуры.

    Проверки:
    1. Глубина вложенности <= MAX_JSON_DEPTH (защита от stack overflow)
    2. Длина строк <= MAX_STRING_LENGTH (защита от memory exhaustion)
    3. Длина чисел <= MAX_NUMBER_DIGITS (CVE-2020-10735)
    4. Размер массивов <= MAX_ARRAY_ITEMS
    5. Количество ключей в dict <= MAX_OBJECT_KEYS

    Args:
        obj: JSON объект для проверки
        depth: Текущая глубина рекурсии
        path: Путь к текущему узлу (для отладки)

    Raises:
        SecurityError: При обнаружении опасной структуры
    """
    # SECURITY: Проверка глубины вложенности
    if depth > MAX_JSON_DEPTH:
        raise SecurityError(
            f"JSON слишком глубоко вложен (>{MAX_JSON_DEPTH} уровней) в {path}"
        )

    if isinstance(obj, str):
        # SECURITY: Проверка длины строки
        if len(obj) > MAX_STRING_LENGTH:
            raise SecurityError(
                f"Строка слишком длинная ({len(obj)} символов > {MAX_STRING_LENGTH}) в {path}"
            )

    elif isinstance(obj, (int, float)):
        # SECURITY: Проверка длины числа (CVE-2020-10735)
        str_num = str(obj)
        if len(str_num) > MAX_NUMBER_DIGITS:
            raise SecurityError(
                f"Число слишком длинное ({len(str_num)} цифр > {MAX_NUMBER_DIGITS}) в {path}"
            )

    elif isinstance(obj, list):
        # SECURITY: Проверка размера массива
        if len(obj) > MAX_ARRAY_ITEMS:
            raise SecurityError(
                f"Массив слишком большой ({len(obj)} элементов > {MAX_ARRAY_ITEMS}) в {path}"
            )

        # Рекурсивная проверка элементов
        for idx, item in enumerate(obj):
            validate_json_object(item, depth + 1, f"{path}[{idx}]")

    elif isinstance(obj, dict):
        # SECURITY: Проверка количества ключей
        if len(obj) > MAX_OBJECT_KEYS:
            raise SecurityError(
                f"Объект слишком большой ({len(obj)} ключей > {MAX_OBJECT_KEYS}) в {path}"
            )

        # Рекурсивная проверка значений
        for key, value in obj.items():
            # Проверка длины ключа
            if len(str(key)) > 1000:
                raise SecurityError(f"Ключ слишком длинный в {path}.{key}")

            validate_json_object(value, depth + 1, f"{path}.{key}")


def timeout_handler(signum, frame):
    """Обработчик сигнала таймаута."""
    raise TimeoutError("Превышено время выполнения")


def safe_regex_compile(pattern_str: str, timeout: int = REGEX_TIMEOUT):
    """
    Безопасная компиляция regex с защитой от ReDoS.

    Args:
        pattern_str: Строка regex паттерна
        timeout: Максимальное время компиляции в секундах

    Returns:
        Скомпилированный regex или None при ошибке

    Raises:
        TimeoutError: При превышении времени компиляции
    """
    # Устанавливаем таймаут (только для Unix-like систем)
    if hasattr(signal, 'SIGALRM'):
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

    try:
        pattern = re.compile(pattern_str, re.IGNORECASE)
        return pattern
    except re.error:
        return None
    except TimeoutError:
        raise TimeoutError(f"Regex слишком сложный (timeout {timeout}s)")
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)


def safe_regex_search(pattern, text: str, timeout: int = REGEX_TIMEOUT) -> bool:
    """
    Безопасный поиск по regex с защитой от ReDoS.

    Args:
        pattern: Скомпилированный regex
        text: Текст для поиска
        timeout: Максимальное время поиска

    Returns:
        True если найдено совпадение, False иначе
    """
    if not pattern:
        return False

    # Ограничение длины текста для поиска
    if len(text) > 10000:
        text = text[:10000]  # Обрезаем очень длинные строки

    # Устанавливаем таймаут
    if hasattr(signal, 'SIGALRM'):
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

    try:
        return bool(pattern.search(text))
    except TimeoutError:
        # Если regex зависает - считаем что не найдено
        return False
    finally:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)


class JsonNode:
    """Узел дерева JSON структуры."""

    def __init__(self, key: str, value: any, parent=None, depth: int = 0, index: int = 0):
        self.key = key
        self.value = value
        self.parent = parent
        self.depth = depth
        self.expanded = False
        self.children = None
        self.index = index

    def is_leaf(self) -> bool:
        """Проверка: является ли узел листовым (не dict и не list)."""
        return not isinstance(self.value, (dict, list))

    def build_children(self):
        """Ленивое создание дочерних узлов при первом обращении."""
        if self.children is not None:
            return

        self.children = []

        if isinstance(self.value, dict):
            for k in sorted(self.value.keys()):
                self.children.append(
                    JsonNode(str(k), self.value[k], self, self.depth + 1)
                )
        elif isinstance(self.value, list):
            for idx, item in enumerate(self.value):
                self.children.append(
                    JsonNode(f"[{idx}]", item, self, self.depth + 1)
                )

    def toggle(self):
        """Переключение состояния развернут/свернут."""
        if self.is_leaf():
            return

        if not self.expanded:
            self.build_children()

        self.expanded = not self.expanded

    def get_root_object(self):
        """Получение корневого объекта (depth=0) для текущего узла."""
        node = self
        while node.parent and node.depth > 0:
            node = node.parent
        return node

    def get_relative_path_with_state(self):
        """
        Получение пути от корневого объекта с состоянием expanded.
        Возвращает: [(key, depth, expanded), ...]
        """
        path = []
        node = self
        root_obj = self.get_root_object()

        while node != root_obj and node.parent:
            path.append((node.key, node.depth, node.expanded))
            node = node.parent

        return list(reversed(path))

    def expand_all(self, node_counter: List[int] = None):
        """
        Рекурсивное разворачивание всех потомков с защитой от переполнения.

        Args:
            node_counter: Счетчик узлов [count] для контроля лимита

        Raises:
            SecurityError: При превышении MAX_EXPAND_NODES
        """
        if self.is_leaf():
            return

        # SECURITY: Проверка лимита узлов
        if node_counter is not None:
            if node_counter[0] > MAX_EXPAND_NODES:
                raise SecurityError(
                    f"Превышен лимит узлов при разворачивании: {MAX_EXPAND_NODES}"
                )

        self.expanded = True
        if not self.children:
            self.build_children()

            # Увеличиваем счетчик созданных узлов
            if node_counter is not None:
                node_counter[0] += len(self.children)

        for child in self.children:
            child.expand_all(node_counter)

    def collapse_all(self):
        """Рекурсивное сворачивание всех потомков."""
        self.expanded = False
        if self.children:
            for child in self.children:
                child.collapse_all()

    def collect_leaf_fields(self) -> Set[str]:
        """Сбор всех уникальных имен листовых полей в поддереве."""
        fields = set()

        def walk(node):
            if node.is_leaf():
                if not node.key.startswith('['):
                    fields.add(node.key)
            else:
                if not node.children:
                    node.build_children()
                for child in node.children:
                    walk(child)

        walk(self)
        return fields


class LazyJsonFile:
    """
    Ленивая загрузка JSON объектов из файла.
    Индексирует позиции объектов без загрузки содержимого.
    Использует LRU-кэш для хранения недавно использованных объектов.
    С валидацией каждого объекта на JSON Bomb атаки.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._offsets = []
        self._count = 0
        self._cache = {}
        self._cache_size = 200
        self._build_index()

    def _build_index(self):
        """Построение индекса: определение позиций всех объектов в файле."""
        # Пробуем загрузить как одиночный JSON
        try:
            with open(self.filepath, 'rb') as f:
                # SECURITY: Валидация JSON при загрузке
                data = json.load(f)

                try:
                    validate_json_object(data, path="root")
                except SecurityError as e:
                    raise SecurityError(f"Опасная JSON структура: {e}")

                self._offsets.append(0)
                self._cache[0] = data
                self._count = 1
                self._is_single = True
                print(f"Одиночный JSON: 1 объект (валидирован)")
                return
        except json.JSONDecodeError:
            pass

        # Если не получилось - обрабатываем как JSONL
        self._is_single = False
        with open(self.filepath, 'rb') as f:
            while True:
                pos = f.tell()
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if line:
                    self._offsets.append(pos)
                    self._count += 1

        print(f"JSONL: {self._count} объектов (индексировано)")

    def __len__(self):
        return self._count

    def __getitem__(self, index: int) -> dict:
        """
        Загрузка объекта по индексу (с кэшированием и валидацией).

        Raises:
            SecurityError: Если объект содержит опасные структуры
        """
        if index in self._cache:
            return self._cache[index]

        # Простая стратегия вытеснения
        if len(self._cache) >= self._cache_size:
            self._cache.pop(next(iter(self._cache)))

        # Загружаем объект из файла
        with open(self.filepath, 'rb') as f:
            f.seek(self._offsets[index])
            line = f.readline()

            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Невалидный JSON в объекте [{index}]: {e}")

            # SECURITY: Валидация объекта на JSON Bomb
            try:
                validate_json_object(obj, path=f"object[{index}]")
            except SecurityError as e:
                # Пропускаем опасный объект, но не падаем
                print(f"ПРЕДУПРЕЖДЕНИЕ: Объект [{index}] пропущен: {e}")
                # Возвращаем заглушку
                obj = {"_error": f"Объект пропущен по соображениям безопасности: {e}"}

            self._cache[index] = obj
            return obj

    def search_by_field(self, field_name: str, pattern_str: str, max_results: int = 1000):
        """
        Поиск по конкретному полю во всех объектах файла.
        С защитой от ReDoS.
        """
        matches = []

        # SECURITY: Безопасная компиляция regex с таймаутом
        try:
            pattern = safe_regex_compile(pattern_str)
            use_regex = pattern is not None
        except TimeoutError as e:
            # Regex слишком сложный - используем простой поиск
            print(f"Предупреждение: {e}. Используется простой поиск.")
            use_regex = False
            pattern = None

        # Проходим по всем объектам
        for i in range(self._count):
            if len(matches) >= max_results:
                break

            try:
                obj = self[i]
            except (SecurityError, ValueError):
                # Пропускаем опасные/невалидные объекты
                continue

            def search_recursive(data, path="", parent_key=""):
                nonlocal matches
                if len(matches) >= max_results:
                    return

                if isinstance(data, dict):
                    for key, value in data.items():
                        search_recursive(value, f"{path}.{key}" if path else key, key)
                elif isinstance(data, list):
                    for idx, item in enumerate(data):
                        search_recursive(item, f"{path}[{idx}]", parent_key)
                else:
                    if parent_key == field_name:
                        val_str = str(data)
                        matched = False

                        if use_regex and pattern:
                            # SECURITY: Безопасный поиск с таймаутом
                            matched = safe_regex_search(pattern, val_str)
                        else:
                            matched = pattern_str.lower() in val_str.lower()

                        if matched:
                            matches.append((i, path, data, parent_key))

            search_recursive(obj)

        return matches

    def search_all_fields(self, pattern_str: str, max_results: int = 1000):
        """
        Глобальный поиск по ВСЕМ листовым полям.
        С защитой от ReDoS.
        """
        matches = []
        matched_fields = set()

        # SECURITY: Безопасная компиляция regex
        try:
            pattern = safe_regex_compile(pattern_str)
            use_regex = pattern is not None
        except TimeoutError as e:
            print(f"Предупреждение: {e}. Используется простой поиск.")
            use_regex = False
            pattern = None

        for i in range(self._count):
            if len(matches) >= max_results:
                break

            try:
                obj = self[i]
            except (SecurityError, ValueError):
                # Пропускаем опасные/невалидные объекты
                continue

            def search_recursive(data, path="", parent_key=""):
                nonlocal matches, matched_fields
                if len(matches) >= max_results:
                    return

                if isinstance(data, dict):
                    for key, value in data.items():
                        search_recursive(value, f"{path}.{key}" if path else key, key)
                elif isinstance(data, list):
                    for idx, item in enumerate(data):
                        search_recursive(item, f"{path}[{idx}]", parent_key)
                else:
                    val_str = str(data)
                    matched = False

                    if use_regex and pattern:
                        # SECURITY: Безопасный поиск
                        matched = safe_regex_search(pattern, val_str)
                    else:
                        matched = pattern_str.lower() in val_str.lower()

                    if matched:
                        matches.append((i, path, data, parent_key))
                        if parent_key and not parent_key.startswith('['):
                            matched_fields.add(parent_key)

            search_recursive(obj)

        return matches, matched_fields


def should_show_node(node: 'JsonNode', filter_fields: Set[str]) -> bool:
    """Проверка: должен ли узел отображаться при активном фильтре."""
    if not filter_fields:
        return True

    if node.is_leaf():
        return node.key in filter_fields

    def has_filtered_descendants(n):
        if n.is_leaf():
            return n.key in filter_fields
        if not n.children:
            n.build_children()
        for child in n.children:
            if has_filtered_descendants(child):
                return True
        return False

    return has_filtered_descendants(node)


def build_visible_list(root, filter_fields: Set[str] = None) -> List['JsonNode']:
    """Построение списка видимых узлов с учетом фильтра."""
    visible = []

    def walk(node):
        if filter_fields and not should_show_node(node, filter_fields):
            return

        visible.append(node)

        if node.expanded and node.children:
            for child in node.children:
                walk(child)

    if root.children:
        for child in root.children:
            walk(child)

    return visible


def format_node_line(node: 'JsonNode', width: int, total_objects: int) -> str:
    """Форматирование строки для отображения узла с обрезкой по ширине экрана."""
    indent = "  " * node.depth
    marker = "-" if node.expanded else "+" if not node.is_leaf() else " "
    key_prefix = f"[{node.index}] " if node.depth == 0 and total_objects > 1 else ""

    if isinstance(node.value, dict):
        val_str = f"{{...}} ({len(node.value)} keys)"
    elif isinstance(node.value, list):
        val_str = f"[...] ({len(node.value)} items)"
    else:
        val_str = repr(node.value)

    line = f"{indent}{marker} {key_prefix}{node.key}: {val_str}"

    # Обрезка по ширине экрана
    available_width = width - 1
    if len(line) > available_width:
        line = line[:available_width - 3] + "..."

    return line


def show_full_value_viewer(stdscr, node: 'JsonNode'):
    """Полноэкранный просмотрщик значения узла с прокруткой."""
    h, w = stdscr.getmaxyx()

    win = curses.newwin(h, w, 0, 0)
    win.keypad(True)

    full_value = str(node.value)
    lines = full_value.split('\n')

    scroll_y = 0
    scroll_x = 0

    while True:
        win.clear()
        win.box()

        title = f" Поле: {node.key} (↑↓←→:прокрутка, q/Esc:выход) "
        win.addnstr(0, (w - len(title)) // 2, title[:w-2], w-2, curses.A_BOLD)

        val_type = type(node.value).__name__
        val_len = len(full_value)
        info = f" Тип: {val_type} | Длина: {val_len} символов "
        win.addnstr(1, 2, info[:w-4], w-4)

        text_h = h - 4
        text_w = w - 4

        max_line_width = max(len(line) for line in lines) if lines else 0

        for i in range(text_h):
            line_idx = scroll_y + i
            if line_idx >= len(lines):
                break

            line = lines[line_idx]

            if scroll_x < len(line):
                visible_part = line[scroll_x:scroll_x + text_w]
                win.addnstr(i + 2, 2, visible_part, text_w)

        status = f"Строка {scroll_y+1}/{len(lines)} | Столбец {scroll_x+1}"
        win.addnstr(h-1, 2, status[:w-4], w-4)

        win.refresh()

        ch = win.getch()

        if ch in (ord('q'), ord('Q'), 27):
            break
        elif ch == curses.KEY_UP:
            scroll_y = max(0, scroll_y - 1)
        elif ch == curses.KEY_DOWN:
            scroll_y = min(max(0, len(lines) - text_h), scroll_y + 1)
        elif ch == curses.KEY_LEFT:
            scroll_x = max(0, scroll_x - 1)
        elif ch == curses.KEY_RIGHT:
            scroll_x = min(max(0, max_line_width - text_w), scroll_x + 1)
        elif ch == curses.KEY_PPAGE:
            scroll_y = max(0, scroll_y - text_h)
        elif ch == curses.KEY_NPAGE:
            scroll_y = min(max(0, len(lines) - text_h), scroll_y + text_h)
        elif ch == curses.KEY_HOME:
            scroll_y = 0
            scroll_x = 0
        elif ch == curses.KEY_END:
            scroll_y = max(0, len(lines) - text_h)


def show_field_selector(stdscr, available_fields: List[str], preselected: Set[str] = None) -> Optional[Set[str]]:
    """Диалог выбора полей для фильтрации."""
    h, w = stdscr.getmaxyx()

    win_h = min(len(available_fields) + 4, h - 4)
    win_w = min(60, w - 4)
    win_y = (h - win_h) // 2
    win_x = (w - win_w) // 2

    win = curses.newwin(win_h, win_w, win_y, win_x)
    win.keypad(True)
    win.box()

    selected_fields = preselected.copy() if preselected else set()
    cursor_pos = 0
    scroll_offset = 0

    while True:
        win.clear()
        win.box()

        title = " Выбор полей (пробел=выбрать, Enter=OK, Esc=отмена) "
        win.addnstr(0, (win_w - len(title)) // 2, title, win_w - 2, curses.A_BOLD)

        list_h = win_h - 3
        for i in range(list_h):
            idx = scroll_offset + i
            if idx >= len(available_fields):
                break

            field = available_fields[idx]
            checkbox = "[X]" if field in selected_fields else "[ ]"
            line = f"{checkbox} {field}"

            if idx == cursor_pos:
                win.attron(curses.A_REVERSE)
                win.addnstr(i + 1, 2, line[:win_w-4], win_w - 4)
                win.attroff(curses.A_REVERSE)
            else:
                win.addnstr(i + 1, 2, line[:win_w-4], win_w - 4)

        status = f"Выбрано: {len(selected_fields)}/{len(available_fields)}"
        win.addnstr(win_h - 1, 2, status, win_w - 4)

        win.refresh()

        ch = win.getch()

        if ch == 27:
            return None
        elif ch in (10, 13):
            return selected_fields
        elif ch in (curses.KEY_UP, ord('k')):
            if cursor_pos > 0:
                cursor_pos -= 1
                if cursor_pos < scroll_offset:
                    scroll_offset = cursor_pos
        elif ch in (curses.KEY_DOWN, ord('j')):
            if cursor_pos < len(available_fields) - 1:
                cursor_pos += 1
                if cursor_pos >= scroll_offset + list_h:
                    scroll_offset = cursor_pos - list_h + 1
        elif ch == ord(' '):
            field = available_fields[cursor_pos]
            if field in selected_fields:
                selected_fields.remove(field)
            else:
                selected_fields.add(field)


def navigate_by_path_with_state(root_obj, rel_path):
    """Навигация к узлу по относительному пути с восстановлением состояния."""
    if not rel_path:
        return root_obj

    current = root_obj

    if not current.expanded and not current.is_leaf():
        current.expanded = True
        if not current.children:
            current.build_children()

    for key, target_depth, should_expand in rel_path:
        if not current.children:
            current.build_children()

        if not current.expanded and not current.is_leaf():
            current.expanded = True

        found = False
        for child in current.children:
            if child.key == key and child.depth == target_depth:
                current = child
                found = True

                if not current.is_leaf():
                    if should_expand and not current.expanded:
                        current.expanded = True
                        if not current.children:
                            current.build_children()
                    elif not should_expand and current.expanded:
                        current.expanded = False
                break

        if not found:
            return None

    return current


def expand_path_to_node(node):
    """Разворачивание всех узлов на пути от корня до указанного узла."""
    path = []
    current = node

    while current.parent:
        path.append(current)
        current = current.parent

    for n in reversed(path):
        if n.parent and not n.parent.expanded and not n.parent.is_leaf():
            n.parent.expanded = True
            if not n.parent.children:
                n.parent.build_children()


def find_node_by_path(root_obj, path_str: str):
    """Поиск узла по строковому пути."""
    if not path_str:
        return root_obj

    parts = []
    for part in path_str.split('.'):
        if '[' in part:
            key = part.split('[')[0]
            if key:
                parts.append(key)
            idx_part = part.split('[')[1].rstrip(']')
            parts.append(f"[{idx_part}]")
        else:
            parts.append(part)

    current = root_obj
    if not current.expanded:
        current.toggle()

    for part in parts:
        if not current.children:
            current.build_children()

        if not current.expanded:
            current.expanded = True

        found = False
        for child in current.children:
            if child.key == part:
                current = child
                found = True
                break

        if not found:
            return None

    return current


def input_string(stdscr, prompt: str, y: int, x: int, max_len: int = 50) -> Optional[str]:
    """Ввод строки с клавиатуры."""
    curses.echo()
    curses.curs_set(1)

    stdscr.addstr(y, x, prompt)
    stdscr.refresh()

    input_win = curses.newwin(1, max_len, y, x + len(prompt))
    input_win.keypad(True)

    result = ""

    while True:
        ch = input_win.getch()

        if ch in (10, 13):
            break
        elif ch == 27:
            result = None
            break
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if result:
                result = result[:-1]
                input_win.clear()
                input_win.addstr(0, 0, result)
        elif 32 <= ch <= 126:
            if len(result) < max_len:
                result += chr(ch)
                input_win.addstr(0, 0, result)

        input_win.refresh()

    curses.noecho()
    curses.curs_set(0)
    return result


def draw(stdscr, visible_nodes, cursor_idx: int, top_idx: int, 
         total_objects: int, current_obj_idx: int, filename: str, 
         filter_fields: Set[str], status_msg: str = ""):
    """Отрисовка главного экрана просмотрщика."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    list_height = h - 4

    if cursor_idx < top_idx:
        top_idx = cursor_idx
    elif cursor_idx >= top_idx + list_height:
        top_idx = cursor_idx - list_height + 1

    filter_indicator = f" [фильтр: {len(filter_fields)} полей]" if filter_fields else ""
    title = f"Файл: {os.path.basename(filename)} ({total_objects} объектов){filter_indicator}"
    stdscr.addnstr(0, 0, title[:w-1], w-1, curses.A_BOLD)

    for i in range(list_height):
        node_idx = top_idx + i
        if node_idx >= len(visible_nodes):
            break

        node = visible_nodes[node_idx]
        line = format_node_line(node, w, total_objects)

        if node_idx == cursor_idx:
            stdscr.attron(curses.A_REVERSE)
            stdscr.addnstr(i+1, 0, line, w-1)
            stdscr.attroff(curses.A_REVERSE)
        else:
            stdscr.addnstr(i+1, 0, line, w-1)

    if status_msg:
        stdscr.addnstr(h-3, 0, status_msg[:w-1], w-1, curses.A_BOLD)

    status = f"Текущий: [{current_obj_idx}] | Объектов: {total_objects} | Узлов: {len(visible_nodes)} | {cursor_idx+1}/{len(visible_nodes) or 1}"
    stdscr.addnstr(h-2, 0, status[:w-1], w-1, curses.A_BOLD)

    controls = "↑↓ →← Enter s:поиск F:глоб.поиск f:фильтр a z A Z g n/p q"
    stdscr.addnstr(h-1, 0, controls[:w-1], w-1, curses.A_BOLD)

    stdscr.refresh()
    return top_idx


def load_object_into_tree(json_file, root, obj_idx, loaded_objects):
    """Ленивая загрузка объекта в дерево."""
    if obj_idx not in loaded_objects and obj_idx < len(json_file):
        try:
            obj = json_file[obj_idx]
        except (SecurityError, ValueError) as e:
            # Пропускаем опасный объект
            return None

        node = JsonNode("record", obj, root, 0, obj_idx)
        root.children.append(node)
        loaded_objects.add(obj_idx)
        root.children.sort(key=lambda n: n.index)
        return node
    else:
        return next((n for n in root.children if n.index == obj_idx), None)


def ensure_next_objects_loaded(json_file, root, loaded_objects, current_max_idx, batch_size=5):
    """Упреждающая загрузка следующих объектов."""
    next_idx = current_max_idx + 1
    for i in range(batch_size):
        if next_idx + i < len(json_file):
            load_object_into_tree(json_file, root, next_idx + i, loaded_objects)


def main(stdscr, json_file: LazyJsonFile, filename: str):
    """Главная функция TUI приложения."""
    curses.curs_set(0)
    stdscr.keypad(True)

    if len(json_file) == 0:
        stdscr.addstr(5, 5, "ОШИБКА: Нет JSON объектов!", curses.A_BOLD)
        stdscr.refresh()
        stdscr.getch()
        return

    root = JsonNode("root", None, depth=-1)
    root.children = []
    loaded_objects = set()

    h, w = stdscr.getmaxyx()
    list_height = h - 4
    preload_count = min(max(list_height + 10, 20), len(json_file))

    status_msg = f"Загрузка первых {preload_count} объектов..."
    stdscr.addnstr(h//2, (w - len(status_msg))//2, status_msg, w-1, curses.A_BOLD)
    stdscr.refresh()

    # Предзагрузка с учетом возможных ошибок
    loaded_count = 0
    for i in range(preload_count):
        try:
            obj = json_file[i]
            node = JsonNode("record", obj, root, 0, i)
            root.children.append(node)
            loaded_objects.add(i)
            loaded_count += 1
        except (SecurityError, ValueError):
            # Пропускаем опасные объекты
            continue

    if loaded_count == 0:
        stdscr.clear()
        stdscr.addstr(5, 5, "ОШИБКА: Все объекты содержат опасные структуры!", curses.A_BOLD)
        stdscr.refresh()
        stdscr.getch()
        return

    cursor_idx = 0
    top_idx = 0
    status_msg = ""

    search_results = []
    search_idx = -1
    current_field_name = None
    filter_fields = set()

    while True:
        visible_nodes = build_visible_list(root, filter_fields)
        if cursor_idx >= len(visible_nodes):
            cursor_idx = max(0, len(visible_nodes) - 1)

        current_obj_idx = 0
        if visible_nodes:
            current_node = visible_nodes[cursor_idx]
            root_obj = current_node.get_root_object()
            current_obj_idx = root_obj.index

        top_idx = draw(stdscr, visible_nodes, cursor_idx, top_idx, 
                      len(json_file), current_obj_idx, filename, filter_fields, status_msg)
        status_msg = ""

        ch = stdscr.getch()

        if ch in (ord('q'), ord('Q'), 27):
            break

        elif ch in (curses.KEY_UP, ord('k')):
            cursor_idx = max(0, cursor_idx - 1)

        elif ch in (curses.KEY_DOWN, ord('j')):
            if cursor_idx < len(visible_nodes) - 1:
                cursor_idx += 1

            if visible_nodes and cursor_idx >= len(visible_nodes) - 5:
                max_loaded = max(loaded_objects) if loaded_objects else -1
                ensure_next_objects_loaded(json_file, root, loaded_objects, max_loaded, 5)

        elif ch in (curses.KEY_RIGHT, ord('l')):
            if visible_nodes:
                node = visible_nodes[cursor_idx]
                if not node.is_leaf():
                    node.toggle()

        elif ch in (10, 13):
            if visible_nodes:
                node = visible_nodes[cursor_idx]
                if node.is_leaf():
                    show_full_value_viewer(stdscr, node)
                else:
                    node.toggle()

        elif ch == curses.KEY_LEFT:
            if visible_nodes:
                node = visible_nodes[cursor_idx]
                if node.expanded and node.children:
                    node.toggle()
                elif node.parent and node.parent != root:
                    parent_idx = next((i for i, n in enumerate(visible_nodes) 
                                     if n is node.parent), 0)
                    cursor_idx = parent_idx

        elif ch == ord('f'):
            if root.children:
                first_obj = root.children[0]
                available_fields = sorted(list(first_obj.collect_leaf_fields()))

                if available_fields:
                    selected = show_field_selector(stdscr, available_fields, filter_fields)
                    if selected is not None:
                        filter_fields = selected
                        if filter_fields:
                            status_msg = f"Фильтр: {len(filter_fields)} полей"
                        else:
                            status_msg = "Фильтр отключен"
                else:
                    status_msg = "Нет доступных полей для фильтрации"

        elif ch == ord('F'):
            h_local, w_local = stdscr.getmaxyx()
            pattern = input_string(stdscr, "Глобальный поиск (regex): ", h_local-3, 0, 40)

            if pattern:
                status_msg = "Поиск по всем полям..."
                stdscr.addnstr(h_local-3, 0, status_msg, w_local-1, curses.A_BOLD)
                stdscr.refresh()

                try:
                    raw_matches, matched_fields = json_file.search_all_fields(pattern, 1000)

                    if raw_matches:
                        search_results = []
                        for obj_idx, path_str, value, field_name in raw_matches:
                            obj_node = load_object_into_tree(json_file, root, obj_idx, loaded_objects)
                            if obj_node:
                                target_node = find_node_by_path(obj_node, path_str)
                                if target_node:
                                    search_results.append(target_node)

                        if search_results:
                            filter_fields = matched_fields
                            search_idx = 0
                            target_node = search_results[search_idx]
                            expand_path_to_node(target_node)
                            visible_nodes = build_visible_list(root, filter_fields)
                            cursor_idx = visible_nodes.index(target_node)
                            status_msg = f"Найдено {len(search_results)}, фильтр: {len(matched_fields)} полей (1/{len(search_results)})"
                        else:
                            status_msg = f"Не найдено: '{pattern}'"
                            search_results = []
                            search_idx = -1
                    else:
                        status_msg = f"Не найдено: '{pattern}'"
                        search_results = []
                        search_idx = -1
                except TimeoutError as e:
                    status_msg = f"Ошибка: {e}"

        elif ch == ord('a'):
            if visible_nodes:
                current_node = visible_nodes[cursor_idx]
                root_obj = current_node.get_root_object()

                # SECURITY: Разворачиваем с контролем лимита
                try:
                    node_counter = [0]
                    root_obj.expand_all(node_counter)
                    status_msg = f"Развернут объект [{root_obj.index}] ({node_counter[0]} узлов)"
                except SecurityError as e:
                    status_msg = f"Ошибка: {e}"

        elif ch == ord('z'):
            if visible_nodes:
                current_node = visible_nodes[cursor_idx]
                root_obj = current_node.get_root_object()
                root_obj.collapse_all()
                visible_nodes = build_visible_list(root, filter_fields)
                try:
                    cursor_idx = visible_nodes.index(root_obj)
                except ValueError:
                    cursor_idx = next((i for i, n in enumerate(visible_nodes) 
                                     if n.index == root_obj.index and n.depth == 0), 0)
                status_msg = f"Свернут объект [{root_obj.index}]"

        elif ch == ord('A'):
            # SECURITY Разворачиваем только ЗАГРУЖЕННЫЕ объекты
            try:
                total_nodes = 0
                node_counter = [0]

                for obj_node in root.children:
                    obj_node.expand_all(node_counter)
                    total_nodes += node_counter[0]
                    node_counter[0] = 0

                status_msg = f"Развернуты загруженные объекты ({len(root.children)} шт, {total_nodes} узлов)"
            except SecurityError as e:
                status_msg = f"Ошибка: {e}"

        elif ch == ord('Z'):
            for obj_node in root.children:
                obj_node.collapse_all()
            visible_nodes = build_visible_list(root, filter_fields)
            if visible_nodes:
                cursor_idx = 0
            status_msg = "Свернуты все объекты"

        elif ch == ord('g'):
            h_local, w_local = stdscr.getmaxyx()
            obj_num_str = input_string(stdscr, "Объект #: ", h_local-3, 0, 10)
            if obj_num_str and obj_num_str.isdigit():
                obj_num = int(obj_num_str)
                if 0 <= obj_num < len(json_file):
                    target_obj = load_object_into_tree(json_file, root, obj_num, loaded_objects)
                    if target_obj:
                        if not target_obj.expanded:
                            target_obj.toggle()
                        visible_nodes = build_visible_list(root, filter_fields)
                        cursor_idx = visible_nodes.index(target_obj)
                        status_msg = f"Переход к объекту [{obj_num}]"
                    else:
                        status_msg = f"Объект [{obj_num}] содержит опасные структуры!"
                else:
                    status_msg = f"Объект [{obj_num}] не существует!"

        elif ch == curses.KEY_END:
            last_idx = len(json_file) - 1
            last_obj = load_object_into_tree(json_file, root, last_idx, loaded_objects)
            if last_obj:
                if not last_obj.expanded:
                    last_obj.toggle()
                visible_nodes = build_visible_list(root, filter_fields)
                cursor_idx = visible_nodes.index(last_obj)
                status_msg = f"Переход к последнему объекту [{last_idx}]"

        elif ch == curses.KEY_HOME:
            first_obj = load_object_into_tree(json_file, root, 0, loaded_objects)
            if first_obj:
                if not first_obj.expanded:
                    first_obj.toggle()
                visible_nodes = build_visible_list(root, filter_fields)
                cursor_idx = visible_nodes.index(first_obj)
                status_msg = "Переход к первому объекту [0]"

        elif ch == ord('s'):
            if visible_nodes:
                current_node = visible_nodes[cursor_idx]
                current_field_name = current_node.key

                h_local, w_local = stdscr.getmaxyx()
                pattern = input_string(stdscr, f"Поиск '{current_field_name}' (regex): ", h_local-3, 0, 40)

                if pattern:
                    status_msg = f"Поиск '{current_field_name}' по всем объектам..."
                    stdscr.addnstr(h_local-3, 0, status_msg, w_local-1, curses.A_BOLD)
                    stdscr.refresh()

                    try:
                        raw_matches = json_file.search_by_field(current_field_name, pattern, 1000)

                        if raw_matches:
                            search_results = []
                            for obj_idx, path_str, value, field_name in raw_matches:
                                obj_node = load_object_into_tree(json_file, root, obj_idx, loaded_objects)
                                if obj_node:
                                    target_node = find_node_by_path(obj_node, path_str)
                                    if target_node:
                                        search_results.append(target_node)

                            if search_results:
                                search_idx = 0
                                target_node = search_results[search_idx]
                                expand_path_to_node(target_node)
                                visible_nodes = build_visible_list(root, filter_fields)
                                cursor_idx = visible_nodes.index(target_node)
                                status_msg = f"Найдено {len(search_results)} '{current_field_name}' (1/{len(search_results)})"
                            else:
                                status_msg = f"Не найдено '{current_field_name}': '{pattern}'"
                                search_results = []
                                search_idx = -1
                        else:
                            status_msg = f"Не найдено '{current_field_name}': '{pattern}'"
                            search_results = []
                            search_idx = -1
                    except TimeoutError as e:
                        status_msg = f"Ошибка: {e}"

        elif ch == ord('n'):
            if search_results and search_idx >= 0:
                search_idx = (search_idx + 1) % len(search_results)
                target_node = search_results[search_idx]
                expand_path_to_node(target_node)
                visible_nodes = build_visible_list(root, filter_fields)
                cursor_idx = visible_nodes.index(target_node)
                root_obj = target_node.get_root_object()
                status_msg = f"obj[{root_obj.index}] ({search_idx+1}/{len(search_results)})"
            else:
                status_msg = "Нет результатов поиска. Нажмите 's' или 'F'"

        elif ch == ord('p'):
            if search_results and search_idx >= 0:
                search_idx = (search_idx - 1) % len(search_results)
                target_node = search_results[search_idx]
                expand_path_to_node(target_node)
                visible_nodes = build_visible_list(root, filter_fields)
                cursor_idx = visible_nodes.index(target_node)
                root_obj = target_node.get_root_object()
                status_msg = f"obj[{root_obj.index}] ({search_idx+1}/{len(search_results)})"
            else:
                status_msg = "Нет результатов поиска. Нажмите 's' или 'F'"

        elif ch == curses.KEY_NPAGE:
            if visible_nodes:
                current_node = visible_nodes[cursor_idx]
                current_obj = current_node.get_root_object()
                current_obj_idx = current_obj.index

                if current_obj_idx < len(json_file) - 1:
                    rel_path = current_node.get_relative_path_with_state()
                    next_obj_idx = current_obj_idx + 1
                    next_obj = load_object_into_tree(json_file, root, next_obj_idx, loaded_objects)

                    if next_obj:
                        target_node = navigate_by_path_with_state(next_obj, rel_path)
                        visible_nodes = build_visible_list(root, filter_fields)
                        if target_node and target_node in visible_nodes:
                            cursor_idx = visible_nodes.index(target_node)
                        else:
                            cursor_idx = visible_nodes.index(next_obj)

        elif ch == curses.KEY_PPAGE:
            if visible_nodes:
                current_node = visible_nodes[cursor_idx]
                current_obj = current_node.get_root_object()
                current_obj_idx = current_obj.index

                if current_obj_idx > 0:
                    rel_path = current_node.get_relative_path_with_state()
                    prev_obj_idx = current_obj_idx - 1
                    prev_obj = load_object_into_tree(json_file, root, prev_obj_idx, loaded_objects)

                    if prev_obj:
                        target_node = navigate_by_path_with_state(prev_obj, rel_path)
                        visible_nodes = build_visible_list(root, filter_fields)
                        if target_node and target_node in visible_nodes:
                            cursor_idx = visible_nodes.index(target_node)
                        else:
                            cursor_idx = visible_nodes.index(prev_obj)


def run():
    """Точка входа в приложение."""
    # Проверка версии Python для CVE-2020-10735
    import sys
    if sys.version_info < (3, 11):
        print("⚠️  ПРЕДУПРЕЖДЕНИЕ: Python < 3.11 уязвим к CVE-2020-10735")
        print("   (очень длинные числа могут зависнуть)")
        print("   Рекомендуется обновить Python до 3.11+\n")

    # Проверка аргументов
    if len(sys.argv) < 2:
        print("Использование: python json_viewer_tui.py file.json")
        print()
        print("Ограничения безопасности:")
        print(f"  - Максимальная глубина JSON: {MAX_JSON_DEPTH} уровней")
        print(f"  - Максимальная длина строки: {MAX_STRING_LENGTH / 1024 / 1024:.0f} MB")
        print(f"  - Максимальная длина числа: {MAX_NUMBER_DIGITS} цифр (CVE-2020-10735)")
        print(f"  - Максимум элементов в массиве: {MAX_ARRAY_ITEMS:,}")
        print(f"  - Максимум ключей в объекте: {MAX_OBJECT_KEYS:,}")
        print(f"  - Максимум узлов при expand_all: {MAX_EXPAND_NODES:,}")
        print(f"  - Timeout для regex: {REGEX_TIMEOUT} секунд")
        print(f"  - Запрещены устройства: {', '.join(FORBIDDEN_DEVICES)}")
        sys.exit(1)

    path_arg = sys.argv[1]

    # SECURITY: Валидация пути к файлу
    try:
        validated_path = validate_file_path(path_arg)
    except (SecurityError, ValueError) as e:
        print(f"ОШИБКА: {e}")
        sys.exit(1)

    path = str(validated_path)

    # Инициализация ленивого загрузчика
    try:
        json_file = LazyJsonFile(path)
    except SecurityError as e:
        print(f"ОШИБКА безопасности: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при открытии файла: {e}")
        sys.exit(1)

    if len(json_file) == 0:
        print("Не найдено валидных JSON!")
        sys.exit(1)

    # Запуск TUI приложения
    try:
        curses.wrapper(main, json_file, path)
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем")
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run()
