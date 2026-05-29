"""
Генератор полного пакета ЕСПД (ГОСТ 19.xxx) для WAF-контейнера.
Запуск: python scripts/generate_espd.py
Выходной файл: ЕСПД_WAF_Контейнер.docx
"""

from docx import Document
from docx.shared import Pt, Cm, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import datetime

# ─────────────────────────────────────────────────────────────────────────────
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ФОРМАТИРОВАНИЯ
# ─────────────────────────────────────────────────────────────────────────────

def set_font(run, size=12, bold=False, italic=False, color=None):
    run.font.name = 'Times New Roman'
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    if color:
        run.font.color.rgb = RGBColor(*color)

def add_heading(doc, text, level=1, center=False):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(6)
    if center:
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(text)
    size = {1: 14, 2: 13, 3: 12}.get(level, 12)
    set_font(run, size=size, bold=True)
    return p

def add_paragraph(doc, text='', indent=False, bold=False, italic=False, center=False, size=12):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(3)
    if indent:
        p.paragraph_format.first_line_indent = Cm(1.25)
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    if center:
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    if text:
        run = p.add_run(text)
        set_font(run, size=size, bold=bold, italic=italic)
    return p

def add_bullet(doc, text, level=0):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.left_indent = Cm(1.0 + level * 0.75)
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    run = p.add_run(text)
    set_font(run, size=12)
    return p

def add_table(doc, headers, rows, col_widths=None):
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.style = 'Table Grid'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_row = table.rows[0]
    for i, h in enumerate(headers):
        cell = hdr_row.cells[i]
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(h)
        set_font(run, size=11, bold=True)
    for r_idx, row_data in enumerate(rows):
        row = table.rows[r_idx + 1]
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = cell.paragraphs[0]
            run = p.add_run(str(val))
            set_font(run, size=11)
    if col_widths:
        for i, w in enumerate(col_widths):
            for row in table.rows:
                row.cells[i].width = Cm(w)
    return table

def add_page_break(doc):
    doc.add_page_break()

def set_margins(doc, top=2, bottom=2, left=3, right=1.5):
    for section in doc.sections:
        section.top_margin = Cm(top)
        section.bottom_margin = Cm(bottom)
        section.left_margin = Cm(left)
        section.right_margin = Cm(right)

def title_page(doc, doc_code, doc_name, dev_name='Вотинцева А.С.'):
    p = add_paragraph(doc, 'Министерство образования и науки Российской Федерации', center=True, size=12)
    add_paragraph(doc, 'ГОСТ Р — Единая система программной документации', center=True, size=11, italic=True)
    add_paragraph(doc)
    add_paragraph(doc)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run('WAF-КОНТЕЙНЕР')
    set_font(run, size=16, bold=True)
    p2 = doc.add_paragraph()
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run2 = p2.add_run('защиты от атаки «Форсированного веб-браузинга»')
    set_font(run2, size=14, bold=True)
    p3 = doc.add_paragraph()
    p3.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run3 = p3.add_run('(УБИ.159 — аналог Wallarm Forced Browsing Protection)')
    set_font(run3, size=12, italic=True)
    add_paragraph(doc)
    p4 = doc.add_paragraph()
    p4.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run4 = p4.add_run(doc_name)
    set_font(run4, size=14, bold=True)
    add_paragraph(doc)
    add_paragraph(doc, f'Обозначение: {doc_code}', center=True, size=12)
    add_paragraph(doc)
    add_paragraph(doc)
    add_paragraph(doc, f'Разработчик: {dev_name}', center=True, size=12)
    add_paragraph(doc, f'Дата: {datetime.date.today().strftime("%d.%m.%Y")}', center=True, size=12)
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 1: СПЕЦИФИКАЦИЯ (ГОСТ 19.202-78)
# ─────────────────────────────────────────────────────────────────────────────
def write_specification(doc):
    title_page(doc, 'XXXXXX.XXXXXX.001', 'СПЕЦИФИКАЦИЯ')
    add_heading(doc, 'СПЕЦИФИКАЦИЯ', 1, center=True)
    add_paragraph(doc, 'к WAF-контейнеру защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)
    add_paragraph(doc,
        'Настоящая спецификация распространяется на программное изделие «WAF-контейнер» '
        'и устанавливает состав программного изделия и документации на него. '
        'Спецификация составлена в соответствии с требованиями '
        'ГОСТ 19.202-78 «Единая система программной документации. '
        'Спецификация. Требования к содержанию и оформлению».',
        indent=True)
    add_paragraph(doc)

    add_heading(doc, '1 Документация', 2)
    add_table(doc,
        ['Обозначение', 'Наименование', 'Примечание'],
        [
            ['XXXXXX.XXXXXX.001', 'Спецификация', 'Настоящий документ'],
            ['XXXXXX.XXXXXX.002', 'Техническое задание', 'WAF-контейнер'],
            ['XXXXXX.XXXXXX.003', 'Текст программы', 'Исходный код WAF-контейнера'],
            ['XXXXXX.XXXXXX.004', 'Описание программы', 'WAF-контейнер'],
            ['XXXXXX.XXXXXX.005', 'Пояснительная записка', 'WAF-контейнер'],
            ['XXXXXX.XXXXXX.006', 'Программа и методика испытаний', 'WAF-контейнер'],
            ['XXXXXX.XXXXXX.ЭД1', 'Ведомость эксплуатационных документов', '—'],
            ['XXXXXX.XXXXXX.ЭД2', 'Формуляр', '—'],
            ['XXXXXX.XXXXXX.ЭД3', 'Руководство оператора', '—'],
            ['XXXXXX.XXXXXX.ЭД4', 'Руководство программиста', '—'],
        ],
        col_widths=[5, 7.5, 5])

    add_heading(doc, '2 Комплексы', 2)
    add_paragraph(doc, 'Комплексы в состав программного изделия не входят.')

    add_heading(doc, '3 Компоненты', 2)
    add_table(doc,
        ['Обозначение', 'Наименование', 'Описание'],
        [
            ['waf.middleware', 'ForcedBrowsingProtectionMiddleware',
             'Перехват HTTP-запросов, проксирование, вызов движка защиты'],
            ['waf.protection', 'ProtectionEngine (Singleton)',
             'Скользящее окно, проверка порогов, блокировка IP'],
            ['waf.protection', 'IPTracker',
             'Трекер активности одного IP: deque уникальных URL и 404-ошибок'],
            ['waf.models', 'BlockedIP',
             'Модель заблокированных IP-адресов (SQLite)'],
            ['waf.models', 'SecurityEvent',
             'Журнал событий безопасности (аудит-трейл)'],
            ['waf.models', 'RequestLog',
             'Полный лог HTTP-запросов для графиков дашборда'],
            ['waf.models', 'TrustedIP',
             'Белый список доверенных IP-адресов и подсетей'],
            ['waf.views', 'dashboard / api_*',
             'HTML-дашборд и 6 REST API-эндпоинтов управления'],
            ['waf.logger', 'JsonFormatter / log_event',
             'ELK-совместимый JSON-форматтер событий безопасности'],
            ['config/waf_config.yaml', 'Конфигурационный файл',
             'Пороги, режим работы, whitelist, backend URL'],
        ],
        col_widths=[4.5, 5, 8])

    add_heading(doc, '4 Примечания', 2)
    add_bullet(doc, 'Спецификация составлена в соответствии с ГОСТ 19.202-78.')
    add_bullet(doc, 'Обозначения программных документов носят условный характер.')
    add_bullet(doc, 'Документы разрабатываются в соответствии с ГОСТ 19.101-2024.')
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 2: ТЕХНИЧЕСКОЕ ЗАДАНИЕ (ГОСТ 19.201-78)
# ─────────────────────────────────────────────────────────────────────────────
def write_tz(doc):
    title_page(doc, 'XXXXXX.XXXXXX.002', 'ТЕХНИЧЕСКОЕ ЗАДАНИЕ')
    add_heading(doc, 'ТЕХНИЧЕСКОЕ ЗАДАНИЕ', 1, center=True)
    add_paragraph(doc, 'на разработку WAF-контейнера защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)

    add_heading(doc, '1 Введение', 2)
    add_paragraph(doc,
        'Настоящее техническое задание распространяется на разработку программного изделия '
        '«WAF-контейнер защиты от атаки форсированного веб-браузинга» (далее — WAF-контейнер). '
        'Программное изделие предназначено для обнаружения и блокирования атак класса '
        '«Форсированный веб-браузинг» (УБИ.159 по методике ФСТЭК России) на веб-приложения.',
        indent=True)
    add_paragraph(doc,
        'Область применения: информационные системы, требующие защиты веб-интерфейсов '
        'от автоматизированного перебора URL-адресов и сканирования скрытых ресурсов.',
        indent=True)

    add_heading(doc, '2 Основания для разработки', 2)
    add_paragraph(doc,
        'Основанием для разработки является учебное задание по дисциплине «Информационная безопасность». '
        'Тема разработки: «WAF-контейнер защиты от атаки форсированного веб-браузинга (УБИ.159)».',
        indent=True)
    add_table(doc,
        ['Параметр', 'Значение'],
        [
            ['Документ-основание', 'Учебное задание'],
            ['Организация-разработчик', 'Вотинцева А.С.'],
            ['Наименование темы', 'WAF-контейнер (аналог Wallarm Forced Browsing Protection)'],
            ['Угроза', 'УБИ.159 — Форсированный веб-браузинг'],
        ], col_widths=[7, 10.5])

    add_heading(doc, '3 Назначение разработки', 2)
    add_paragraph(doc,
        'Функциональное назначение: обнаружение и блокирование атак форсированного веб-браузинга '
        'путём анализа входящих HTTP-запросов с применением метода скользящего временного окна.',
        indent=True)
    add_paragraph(doc,
        'Эксплуатационное назначение: развёртывание в качестве обратного прокси-сервера '
        'перед защищаемым веб-приложением с минимальной конфигурацией через YAML-файл.',
        indent=True)

    add_heading(doc, '4 Требования к программе', 2)

    add_heading(doc, '4.1 Требования к функциональным характеристикам', 3)
    add_paragraph(doc, 'WAF-контейнер должен выполнять следующие функции:', indent=True)
    funcs = [
        'перехват всех входящих HTTP-запросов до передачи защищаемому приложению;',
        'подсчёт уникальных URL per-IP в скользящем временном окне (по умолчанию 60 с);',
        'подсчёт доли ответов с кодом 404 (HTTP Not Found) в скользящем окне;',
        'вычисление частоты запросов (RPS — requests per second) на IP;',
        'автоматическая блокировка IP при превышении любого из трёх пороговых значений;',
        'проксирование разрешённых запросов на защищаемый backend-сервер;',
        'ведение журнала событий безопасности в формате JSON (ELK-совместимый);',
        'HTML-дашборд с Chart.js-визуализацией статистики и управлением блокировками;',
        'три режима работы: block (блокировка), monitoring (мониторинг), disabled (отключён);',
        'REST API для управления блокировками и получения статистики;',
        'поддержка белого списка IP-адресов и подсетей (CIDR-нотация);',
        'горячая перезагрузка конфигурации без перезапуска сервиса.',
    ]
    for f in funcs:
        add_bullet(doc, f)

    add_paragraph(doc, 'Пороговые значения по умолчанию:', indent=True)
    add_table(doc,
        ['Параметр', 'Значение по умолчанию', 'Описание'],
        [
            ['unique_urls', '50', 'Максимальное число уникальных URL за окно'],
            ['error_rate_percent', '70%', 'Максимальная доля ответов 404'],
            ['min_requests_for_rate', '10', 'Минимум запросов для активации rate-проверки'],
            ['rps', '30', 'Максимальная частота запросов (запросов/сек)'],
            ['window_seconds', '60', 'Размер скользящего временного окна (сек)'],
            ['block_duration_seconds', '3600', 'Длительность автоматической блокировки (сек)'],
        ], col_widths=[5, 4.5, 8])

    add_heading(doc, '4.2 Требования к надёжности', 3)
    add_bullet(doc, 'Отказ подсистемы логирования не должен прерывать обработку запросов.')
    add_bullet(doc, 'Отказ backend-сервера должен возвращать код 502 Bad Gateway без краша WAF.')
    add_bullet(doc, 'Счётчики защищены мьютексами (threading.Lock) для потокобезопасности.')
    add_bullet(doc, 'Фоновый поток очистки устаревших данных завершается вместе с процессом (daemon=True).')
    add_bullet(doc, 'Конфиг читается с fallback на безопасные значения по умолчанию при ошибке парсинга.')

    add_heading(doc, '4.3 Условия эксплуатации', 3)
    add_table(doc,
        ['Параметр', 'Требование'],
        [
            ['Операционная система', 'Linux (рекомендуется), Windows, macOS'],
            ['Сеть', 'TCP/IP, порт 8000 (настраиваемый)'],
            ['Количество персонала', 'Минимум 1 администратор'],
            ['Квалификация', 'Знание основ HTTP, опыт работы с Linux CLI'],
            ['Режим работы', 'Непрерывный (24/7)'],
        ], col_widths=[5.5, 12])

    add_heading(doc, '4.4 Требования к составу и параметрам технических средств', 3)
    add_table(doc,
        ['Компонент', 'Минимальные требования'],
        [
            ['ЦП', 'x86-64, 1 ядро, 1 ГГц'],
            ['ОЗУ', '256 МБ (рекомендуется 512 МБ)'],
            ['Диск', '500 МБ свободного места'],
            ['Сеть', '100 Мбит/с Ethernet'],
            ['ПО', 'Python 3.11+, pip'],
        ], col_widths=[5.5, 12])

    add_heading(doc, '4.5 Требования к информационной и программной совместимости', 3)
    add_bullet(doc, 'Язык программирования: Python 3.11.')
    add_bullet(doc, 'Веб-фреймворк: Django 4.2.x.')
    add_bullet(doc, 'СУБД: SQLite 3 (встроена в Python); возможна замена на PostgreSQL.')
    add_bullet(doc, 'Формат конфигурации: YAML (PyYAML ≥ 6.0).')
    add_bullet(doc, 'Входные данные: HTTP/1.1 и HTTP/2 запросы.')
    add_bullet(doc, 'Выходные данные: JSON-события безопасности (NDJSON, ELK-совместимые).')
    add_bullet(doc, 'HTTP-клиент для проксирования: requests ≥ 2.31.')
    add_bullet(doc, 'Статические файлы: WhiteNoise ≥ 6.0.')

    add_heading(doc, '5 Требования к программной документации', 2)
    add_paragraph(doc, 'В состав программной документации должны входить:', indent=True)
    docs = [
        'Спецификация (ГОСТ 19.202-78)',
        'Техническое задание (ГОСТ 19.201-78)',
        'Текст программы (ГОСТ 19.401-78)',
        'Описание программы (ГОСТ 19.402-78)',
        'Пояснительная записка (ГОСТ 19.404-79)',
        'Программа и методика испытаний (ГОСТ 19.301-79)',
        'Руководство оператора (ГОСТ 19.505-79)',
        'Руководство программиста (ГОСТ 19.504-79)',
        'Формуляр (ГОСТ 19.501-78)',
    ]
    for d in docs:
        add_bullet(doc, d)

    add_heading(doc, '6 Технико-экономические показатели', 2)
    add_paragraph(doc,
        'Экономическая эффективность обеспечивается снижением ущерба от атак '
        'форсированного веб-браузинга: предотвращение утечки конфиденциальных '
        'файлов, исключение несанкционированного доступа к административным интерфейсам. '
        'Ориентировочный эффект — снижение успешных атак класса УБИ.159 на ≥ 95%.',
        indent=True)

    add_heading(doc, '7 Стадии и этапы разработки', 2)
    add_table(doc,
        ['Стадия', 'Этап', 'Содержание работ'],
        [
            ['Техническое задание', 'Анализ угроз', 'Изучение УБИ.159, Wallarm Forced Browsing Protection'],
            ['Эскизный проект', 'Проектирование', 'Архитектура middleware, алгоритм скользящего окна'],
            ['Технический проект', 'Детальное проектирование', 'Схемы модулей, модели данных, API'],
            ['Рабочий проект', 'Кодирование', 'Реализация всех компонентов, тесты'],
            ['Внедрение', 'Испытания', 'Функциональное тестирование, нагрузочные тесты'],
        ], col_widths=[4.5, 4.5, 8.5])

    add_heading(doc, '8 Порядок контроля и приёмки', 2)
    add_paragraph(doc,
        'Приёмка выполняется путём проведения испытаний согласно «Программе и методике испытаний» '
        '(XXXXXX.XXXXXX.006). Виды испытаний: функциональное тестирование, симуляция атаки, '
        'проверка режимов работы, проверка API.',
        indent=True)
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 3: ТЕКСТ ПРОГРАММЫ (ГОСТ 19.401-78)
# ─────────────────────────────────────────────────────────────────────────────
def write_text_program(doc):
    title_page(doc, 'XXXXXX.XXXXXX.003', 'ТЕКСТ ПРОГРАММЫ')
    add_heading(doc, 'ТЕКСТ ПРОГРАММЫ', 1, center=True)
    add_paragraph(doc, 'WAF-контейнер защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)
    add_paragraph(doc,
        'Настоящий документ содержит текст программы WAF-контейнера. '
        'Составлен в соответствии с ГОСТ 19.401-78.',
        indent=True)

    sections = [
        ('Модуль 1: waf/protection.py — Движок защиты (ProtectionEngine)', [
            '# Класс IPTracker — трекер активности одного IP',
            'class IPTracker:',
            '    def __init__(self, window_seconds: int):',
            '        self.window_seconds = window_seconds',
            '        self.lock = threading.Lock()',
            '        self.unique_urls: set = set()',
            '        self.error_404_times: deque = deque()',
            '        self.all_request_times: deque = deque()',
            '',
            '    def add_request(self, url, status_code, ts):',
            '        with self.lock:',
            '            cutoff = ts - self.window_seconds',
            '            # Удаление устаревших записей (скользящее окно)',
            '            while self.all_request_times and \\',
            '                  self.all_request_times[0] < cutoff:',
            '                self.all_request_times.popleft()',
            '            self.all_request_times.append(ts)',
            '            if status_code == 404:',
            '                self.error_404_times.append(ts)',
            '            self.unique_urls.add(url)',
            '',
            '# Класс ProtectionEngine — Singleton движка защиты',
            'class ProtectionEngine:',
            '    _instance = None',
            '    _lock = threading.Lock()',
            '',
            '    @classmethod',
            '    def get_instance(cls):',
            '        if cls._instance is None:',
            '            with cls._lock:',
            '                if cls._instance is None:',
            '                    cls._instance = cls()',
            '        return cls._instance',
            '',
            '    def check_and_record(self, ip, url, path, method,',
            '                          status_code, user_agent=""):',
            '        """Главный метод: анализирует запрос, возвращает решение."""',
            '        result = {"action": "allow", "reason": None, "stats": {}}',
            '        if self._is_whitelisted(ip):',
            '            result["action"] = "whitelist"',
            '            return result',
            '        if self.is_blocked(ip):',
            '            result["action"] = "block"',
            '            return result',
            '        tracker = self._get_tracker(ip)',
            '        tracker.add_request(url, status_code, time.time())',
            '        stats = tracker.get_stats(time.time())',
            '        # Проверка трёх порогов обнаружения атаки',
            '        thresholds = self.config.get("thresholds", {})',
            '        if stats["unique_urls"] >= thresholds.get("unique_urls", 50):',
            '            violation_reason = "unique_url_limit"',
            '        elif stats["error_rate"] >= thresholds.get("error_rate_percent", 70):',
            '            violation_reason = "error_rate_limit"',
            '        elif rps >= thresholds.get("rps", 30):',
            '            violation_reason = "rps_limit"',
            '        if violation_reason and mode == "block":',
            '            self._block_ip(ip, violation_reason, stats)',
            '            result["action"] = "block"',
            '        return result',
        ]),
        ('Модуль 2: waf/middleware.py — Middleware перехвата запросов', [
            'class ForcedBrowsingProtectionMiddleware:',
            '    def __init__(self, get_response):',
            '        self.get_response = get_response',
            '',
            '    def __call__(self, request):',
            '        from waf.protection import ProtectionEngine',
            '        engine = ProtectionEngine.get_instance()',
            '        ip = get_client_ip(request)',
            '        # Проверка исключённых путей (/waf/, /admin/, /static/)',
            '        if any(request.path.startswith(e)',
            '               for e in engine.config.get("excluded_paths", [])):',
            '            return self.get_response(request)',
            '        # Предварительная проверка блокировки',
            '        if engine.is_blocked(ip):',
            '            return self._blocked_response(engine)',
            '        # Demo-режим: Django сам обрабатывает запрос',
            '        if not backend_url:',
            '            response = self.get_response(request)',
            '            engine.check_and_record(ip, url, path,',
            '                method, response.status_code, user_agent)',
            '            return response',
            '        # Production-режим: проксирование на backend',
            '        proxy_resp = self._proxy_request(request, backend_url)',
            '        check_result = engine.check_and_record(...)',
            '        if check_result["action"] == "block":',
            '            return self._blocked_response(engine)',
            '        return self._build_django_response(proxy_resp)',
        ]),
        ('Модуль 3: waf/models.py — Модели базы данных', [
            'class BlockedIP(models.Model):',
            '    ip_address = models.GenericIPAddressField(unique=True)',
            '    blocked_at = models.DateTimeField(default=timezone.now)',
            '    expires_at = models.DateTimeField(null=True, blank=True)',
            '    reason = models.CharField(max_length=50, choices=BLOCK_REASON_CHOICES)',
            '    is_active = models.BooleanField(default=True)',
            '',
            'class SecurityEvent(models.Model):',
            '    timestamp = models.DateTimeField(default=timezone.now)',
            '    event_type = models.CharField(max_length=30, choices=EVENT_TYPE_CHOICES)',
            '    source_ip = models.GenericIPAddressField()',
            '    url = models.TextField()',
            '    unique_urls_at_time = models.IntegerField(default=0)',
            '    error_rate = models.FloatField(default=0.0)',
            '    details = models.JSONField(default=dict)',
            '',
            'class RequestLog(models.Model):',
            '    source_ip = models.GenericIPAddressField()',
            '    url = models.TextField()',
            '    status_code = models.IntegerField(null=True)',
            '    was_blocked = models.BooleanField(default=False)',
            '    response_time_ms = models.FloatField(null=True)',
        ]),
        ('Модуль 4: waf/logger.py — ELK-совместимое логирование', [
            'class JsonFormatter(logging.Formatter):',
            '    def format(self, record):',
            '        log_entry = {',
            '            "timestamp": datetime.now(timezone.utc).isoformat(),',
            '            "level": record.levelname,',
            '            "logger": record.name,',
            '            "message": record.getMessage(),',
            '        }',
            '        if hasattr(record, "extra"):',
            '            log_entry.update(record.extra)',
            '        return json.dumps(log_entry, ensure_ascii=False)',
            '',
            'def log_event(event_type, ip, url="", **kwargs):',
            '    extra = {"event_type": event_type, "source_ip": ip,',
            '             "url": url, **kwargs}',
            '    security_logger.info(f"{event_type}: {ip} -> {url}",',
            '                         extra={"extra": extra})',
        ]),
    ]

    for title, lines in sections:
        add_heading(doc, title, 2)
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(1.0)
        run = p.add_run('\n'.join(lines))
        run.font.name = 'Courier New'
        run.font.size = Pt(9)
        add_paragraph(doc)

    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 4: ОПИСАНИЕ ПРОГРАММЫ (ГОСТ 19.402-78)
# ─────────────────────────────────────────────────────────────────────────────
def write_description(doc):
    title_page(doc, 'XXXXXX.XXXXXX.004', 'ОПИСАНИЕ ПРОГРАММЫ')
    add_heading(doc, 'ОПИСАНИЕ ПРОГРАММЫ', 1, center=True)
    add_paragraph(doc, 'WAF-контейнер защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)

    add_heading(doc, '1 Общие сведения', 2)
    add_table(doc,
        ['Параметр', 'Значение'],
        [
            ['Обозначение', 'XXXXXX.XXXXXX'],
            ['Наименование', 'WAF-контейнер защиты от атаки форсированного веб-браузинга'],
            ['Аббревиатура', 'WAF (Web Application Firewall)'],
            ['Язык программирования', 'Python 3.11'],
            ['Фреймворк', 'Django 4.2'],
            ['СУБД', 'SQLite 3'],
            ['Конфигурация', 'YAML (waf_config.yaml)'],
            ['Платформа', 'Linux / Windows / macOS'],
            ['Порт по умолчанию', '8000'],
        ], col_widths=[6, 11.5])

    add_heading(doc, '2 Функциональное назначение', 2)
    add_paragraph(doc,
        'WAF-контейнер предназначен для защиты веб-приложений от атак класса '
        '«Форсированный веб-браузинг» (УБИ.159 по методике ФСТЭК России). '
        'Программа реализует аналог функциональности модуля Wallarm Forced Browsing Protection.',
        indent=True)
    add_paragraph(doc, 'Классы решаемых задач:', indent=True)
    add_bullet(doc, 'Обнаружение автоматизированного перебора URL-адресов (словарные атаки).')
    add_bullet(doc, 'Блокирование IP-адресов, превысивших допустимые пороги активности.')
    add_bullet(doc, 'Мониторинг и визуализация трафика в реальном времени.')
    add_bullet(doc, 'Аудит событий безопасности в ELK-совместимом формате.')
    add_paragraph(doc, 'Функциональные ограничения:', indent=True)
    add_bullet(doc, 'Блокировка выполняется на уровне IP (не на уровне сессий/пользователей).')
    add_bullet(doc, 'В текущей версии используется SQLite; для высоконагруженных систем рекомендуется Redis.')

    add_heading(doc, '3 Описание логической структуры', 2)
    add_paragraph(doc, 'Алгоритм работы программы:', indent=True)
    steps = [
        '(1) Перехват запроса в Django Middleware.',
        '(2) Извлечение IP-адреса (с учётом X-Forwarded-For).',
        '(3) Фильтрация исключённых системных путей.',
        '(4) Проверка белого списка (whitelist).',
        '(5) Проверка наличия активной блокировки IP (БД + in-memory).',
        '(6) Обновление IPTracker: добавление URL и timestamp в скользящее окно.',
        '(7) Вычисление метрик: unique_urls, error_rate, RPS.',
        '(8) Сравнение метрик с пороговыми значениями из waf_config.yaml.',
        '(9) При нарушении порога: блокировка IP, запись события в БД и JSON-лог.',
        '(10) Проксирование разрешённых запросов на backend или обработка Django.',
        '(11) Возврат клиенту: 403 Forbidden (блокировка) или ответ backend.',
    ]
    for s in steps:
        add_bullet(doc, s)

    add_paragraph(doc, 'Используемые методы:', indent=True)
    add_bullet(doc, 'Скользящее временное окно (Sliding Window) на основе deque — O(1) добавление/удаление.')
    add_bullet(doc, 'Паттерн Singleton для ProtectionEngine — единое состояние счётчиков в процессе.')
    add_bullet(doc, 'Double-checked locking — потокобезопасное создание Singleton без избыточной блокировки.')
    add_bullet(doc, 'Множество (set) для подсчёта уникальных URL — автоматическая дедупликация за O(1).')

    add_paragraph(doc, 'Структура модулей и связи:', indent=True)
    add_table(doc,
        ['Модуль', 'Зависит от', 'Описание связи'],
        [
            ['middleware.py', 'protection.py', 'Вызов check_and_record() для каждого запроса'],
            ['middleware.py', 'models.py', 'Запись RequestLog через _save_request_log()'],
            ['protection.py', 'models.py', 'Запись BlockedIP и SecurityEvent'],
            ['protection.py', 'logger.py', 'Вызов log_event() при блокировке/атаке'],
            ['views.py', 'protection.py', 'Получение статистики, ручное управление блокировками'],
            ['views.py', 'models.py', 'Агрегация данных для дашборда'],
            ['settings.py', 'middleware.py', 'Регистрация в MIDDLEWARE[]'],
            ['waf_config.yaml', 'protection.py', 'Загрузка при инициализации ProtectionEngine'],
        ], col_widths=[4.5, 4.5, 8.5])

    add_heading(doc, '4 Используемые технические средства', 2)
    add_paragraph(doc,
        'Программа функционирует на ПЭВМ архитектуры x86-64 под управлением '
        'операционной системы Linux (рекомендуется Ubuntu 22.04 LTS / Debian 12). '
        'Дополнительного специализированного оборудования не требуется.',
        indent=True)

    add_heading(doc, '5 Вызов и загрузка', 2)
    add_paragraph(doc, 'Запуск сервера разработки:', indent=True)
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(2)
    r = p.add_run('python manage.py runserver 0.0.0.0:8000')
    r.font.name = 'Courier New'; r.font.size = Pt(11)

    add_paragraph(doc, 'Инициализация БД (первый запуск):', indent=True)
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(2)
    r = p.add_run('python manage.py migrate\npython manage.py seed_demo  # загрузка демо-данных')
    r.font.name = 'Courier New'; r.font.size = Pt(11)

    add_paragraph(doc,
        'ProtectionEngine инициализируется автоматически при обработке первого запроса '
        'через метод get_instance() (Singleton). Конфигурация загружается из '
        'config/waf_config.yaml.',
        indent=True)

    add_heading(doc, '6 Входные данные', 2)
    add_table(doc,
        ['Входной поток', 'Формат', 'Описание'],
        [
            ['HTTP-запрос', 'HTTP/1.1, HTTP/2', 'Входящий запрос от клиента: метод, URL, заголовки'],
            ['waf_config.yaml', 'YAML', 'Конфигурация: пороги, режим, whitelist, backend URL'],
            ['X-Forwarded-For', 'HTTP-заголовок', 'Реальный IP клиента за обратным прокси'],
            ['Тело запроса', 'произвольный', 'Для POST/PUT/PATCH — передаётся на backend as-is'],
        ], col_widths=[4.5, 4, 9])

    add_heading(doc, '7 Выходные данные', 2)
    add_table(doc,
        ['Выходной поток', 'Формат', 'Описание'],
        [
            ['HTTP-ответ клиенту', 'HTTP/1.1', '200 OK (разрешён) / 403 Forbidden (заблокирован)'],
            ['security_events.json', 'NDJSON', 'Структурированные события безопасности (ELK)'],
            ['SQLite BlockedIP', 'SQL', 'Заблокированные IP: адрес, причина, срок'],
            ['SQLite SecurityEvent', 'SQL', 'Журнал событий: тип, IP, URL, метрики'],
            ['SQLite RequestLog', 'SQL', 'Лог запросов: метод, URL, статус, время'],
            ['REST API /waf/api/stats/', 'JSON', 'Агрегированная статистика для дашборда'],
            ['HTML дашборд /waf/', 'HTML+JS', 'Визуализация: Chart.js графики, таблицы'],
        ], col_widths=[5, 3, 9.5])
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 5: ПОЯСНИТЕЛЬНАЯ ЗАПИСКА (ГОСТ 19.404-79)
# ─────────────────────────────────────────────────────────────────────────────
def write_explanatory_note(doc):
    title_page(doc, 'XXXXXX.XXXXXX.005', 'ПОЯСНИТЕЛЬНАЯ ЗАПИСКА')
    add_heading(doc, 'ПОЯСНИТЕЛЬНАЯ ЗАПИСКА', 1, center=True)
    add_paragraph(doc, 'WAF-контейнер защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)

    add_heading(doc, '1 Введение', 2)
    add_paragraph(doc,
        'Настоящая пояснительная записка относится к программному изделию '
        '«WAF-контейнер защиты от атаки форсированного веб-браузинга» и составлена '
        'на стадии технического проекта согласно ГОСТ 19.404-79.',
        indent=True)
    add_paragraph(doc,
        'Атака «Форсированный веб-браузинг» (УБИ.159 по банку угроз ФСТЭК России) '
        'заключается в автоматизированном переборе URL-адресов с целью получения '
        'несанкционированного доступа к скрытым ресурсам веб-приложения: '
        'административным панелям, конфигурационным файлам, резервным копиям, '
        'API-эндпоинтам без аутентификации.',
        indent=True)

    add_heading(doc, '2 Назначение и область применения', 2)
    add_paragraph(doc,
        'WAF-контейнер предназначен для встраивания в инфраструктуру веб-приложений '
        'в качестве обратного прокси-сервера. Область применения: '
        'корпоративные информационные системы, интернет-порталы, '
        'сервисы электронного правительства.',
        indent=True)

    add_heading(doc, '3 Технические характеристики', 2)

    add_heading(doc, '3.1 Постановка задачи', 3)
    add_paragraph(doc,
        'Задача — разработать программный модуль, реализующий следующий алгоритм '
        'обнаружения атаки форсированного браузинга:',
        indent=True)
    add_paragraph(doc,
        'Для каждого IP-адреса поддерживается скользящее временное окно размером W секунд. '
        'В окне отслеживаются: множество уникальных URL U(ip,t), '
        'последовательности временны́х меток запросов T(ip,t) и '
        'ошибок 404 E(ip,t). '
        'IP блокируется если выполняется хотя бы одно из условий:',
        indent=True)
    add_bullet(doc, '|U(ip,t)| ≥ unique_url_threshold (по умолчанию 50)')
    add_bullet(doc, '|E(ip,t)| / |T(ip,t)| × 100% ≥ error_rate_threshold (по умолчанию 70%)')
    add_bullet(doc, '|T(ip,t)| / W ≥ rps_threshold (по умолчанию 30 запросов/сек)')

    add_heading(doc, '3.2 Описание алгоритма и функционирования', 3)
    add_paragraph(doc,
        'Алгоритм построен на структуре данных «скользящее окно» (Sliding Window). '
        'Реализация использует collections.deque — двустороннюю очередь с O(1) '
        'операциями добавления в конец и удаления с начала. Все операции со '
        'счётчиками защищены threading.Lock для потокобезопасности в '
        'многопоточном WSGI-окружении Django.',
        indent=True)
    add_paragraph(doc,
        'ProtectionEngine реализован по паттерну Singleton с double-checked locking, '
        'что обеспечивает единственный экземпляр и общую память счётчиков между '
        'воркерами одного процесса Django. В production-среде с несколькими '
        'процессами рекомендуется замена in-memory счётчиков на Redis.',
        indent=True)

    add_heading(doc, '3.3 Организация входных и выходных данных', 3)
    add_paragraph(doc,
        'Входные данные: поток HTTP-запросов, принимаемых Django-сервером. '
        'Каждый запрос обрабатывается синхронно в цепочке middleware. '
        'Конфигурация загружается из YAML-файла при старте движка.',
        indent=True)
    add_paragraph(doc,
        'Выходные данные: '
        '(1) HTTP-ответы клиентам (403/200/проксированный ответ); '
        '(2) записи в SQLite-таблицах (BlockedIP, SecurityEvent, RequestLog); '
        '(3) JSON-события в файле logs/security_events.json; '
        '(4) данные REST API для дашборда.',
        indent=True)

    add_heading(doc, '3.4 Обоснование выбора технических и программных средств', 3)
    add_table(doc,
        ['Компонент', 'Выбор', 'Обоснование'],
        [
            ['Язык', 'Python 3.11', 'Богатая экосистема, встроенные threading, collections'],
            ['Фреймворк', 'Django 4.2', 'Встроенные middleware, ORM, admin; зрелость'],
            ['СУБД', 'SQLite', 'Достаточна для лаборатории; нет внешних зависимостей'],
            ['Конфиг', 'YAML', 'Читаемость, поддержка вложенных структур, комментарии'],
            ['Статика', 'WhiteNoise', 'Раздача static без nginx в dev/prod'],
            ['Визуализация', 'Chart.js', 'Клиентская библиотека без серверного рендеринга'],
            ['Логи', 'NDJSON', 'ELK-совместимость: прямой импорт в Logstash/Filebeat'],
        ], col_widths=[3.5, 4, 10])

    add_heading(doc, '4 Ожидаемые технико-экономические показатели', 2)
    add_table(doc,
        ['Показатель', 'Значение'],
        [
            ['Задержка на запрос (overhead)', '< 1 мс (in-memory операции)'],
            ['Пропускная способность', '> 1000 RPS на одном ядре ЦП'],
            ['Память на 10 000 активных IP', '≈ 50 МБ (deque + set)'],
            ['Время до блокировки', '≤ 60 секунд (размер окна)'],
            ['Точность обнаружения', '≥ 95% (при настройках по умолчанию)'],
            ['Ложные блокировки', '< 0.1% легитимного трафика'],
        ], col_widths=[7, 10.5])

    add_heading(doc, '5 Источники, использованные при разработке', 2)
    sources = [
        'ГОСТ 19.101-2024. Единая система программной документации. Виды программ и программных документов.',
        'ГОСТ 19.201-78. ЕСПД. Техническое задание. Требования к содержанию и оформлению.',
        'ГОСТ 19.402-78. ЕСПД. Описание программы.',
        'Банк данных угроз безопасности информации ФСТЭК России. УБИ.159 — Угроза форсированного веб-браузинга.',
        'Django Documentation. Version 4.2. djangoproject.com, 2024.',
        'Wallarm Documentation. Forced Browsing Attack Protection. docs.wallarm.com, 2024.',
        'Beazley D., Jones B.K. Python Cookbook, 3rd Ed. O\'Reilly Media, 2013.',
        'OWASP Testing Guide v4.2. Testing for Forced Browsing (OTG-AUTHZ-004). owasp.org, 2021.',
    ]
    for i, s in enumerate(sources, 1):
        add_paragraph(doc, f'{i}. {s}', indent=True)
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 6: ПРОГРАММА И МЕТОДИКА ИСПЫТАНИЙ (ГОСТ 19.301-79)
# ─────────────────────────────────────────────────────────────────────────────
def write_test_program(doc):
    title_page(doc, 'XXXXXX.XXXXXX.006', 'ПРОГРАММА И МЕТОДИКА ИСПЫТАНИЙ')
    add_heading(doc, 'ПРОГРАММА И МЕТОДИКА ИСПЫТАНИЙ', 1, center=True)
    add_paragraph(doc, 'WAF-контейнер защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)

    add_heading(doc, '1 Объект испытаний', 2)
    add_paragraph(doc,
        'Объект испытаний: программное изделие «WAF-контейнер защиты от атаки '
        'форсированного веб-браузинга», обозначение XXXXXX.XXXXXX. '
        'Область применения: защита веб-приложений от атак класса УБИ.159.',
        indent=True)

    add_heading(doc, '2 Цель испытаний', 2)
    add_paragraph(doc,
        'Цель испытаний: проверка соответствия WAF-контейнера требованиям, '
        'изложенным в техническом задании (XXXXXX.XXXXXX.002), '
        'по функциональности, надёжности и корректности обнаружения атак.',
        indent=True)

    add_heading(doc, '3 Требования к программе', 2)
    add_bullet(doc, 'Блокировка IP при превышении порога уникальных URL (≥ 50).')
    add_bullet(doc, 'Блокировка IP при превышении доли 404-ошибок (≥ 70%, мин. 10 запросов).')
    add_bullet(doc, 'Блокировка IP при превышении RPS (≥ 30 запросов/сек).')
    add_bullet(doc, 'В режиме monitoring: события фиксируются, блокировка не выполняется.')
    add_bullet(doc, 'В режиме disabled: WAF прозрачен, все запросы пропускаются.')
    add_bullet(doc, 'IP из whitelist не блокируется никогда.')
    add_bullet(doc, 'Корректная запись событий в SQLite и JSON-лог.')
    add_bullet(doc, 'REST API возвращает корректные данные статистики.')
    add_bullet(doc, 'HTML-дашборд отображается без ошибок на /waf/.')

    add_heading(doc, '4 Требования к программной документации', 2)
    add_paragraph(doc,
        'На испытания предъявляется полный комплект документации ЕСПД: '
        'Спецификация, ТЗ, Текст программы, Описание программы, '
        'Пояснительная записка, Руководство оператора, Руководство программиста.',
        indent=True)

    add_heading(doc, '5 Состав и порядок испытаний', 2)
    add_table(doc,
        ['№', 'Тест', 'Входные данные', 'Ожидаемый результат'],
        [
            ['Т-01', 'Блокировка по unique_urls',
             '55 запросов к уникальным URL от одного IP',
             'IP блокируется, HTTP 403, запись в BlockedIP'],
            ['Т-02', 'Блокировка по error_rate',
             '15 запросов, 12 из них с ответом 404 (80%)',
             'IP блокируется, HTTP 403'],
            ['Т-03', 'Блокировка по RPS',
             '35 запросов в течение 1 секунды',
             'IP блокируется, HTTP 403'],
            ['Т-04', 'Whitelist',
             'Запросы от 127.0.0.1 (в whitelist)',
             'IP не блокируется, все запросы пропускаются'],
            ['Т-05', 'Режим monitoring',
             'mode: monitoring, 55 уникальных URL',
             'Событие записано, блокировки нет, HTTP 200'],
            ['Т-06', 'Режим disabled',
             'mode: disabled, любые запросы',
             'WAF прозрачен, все запросы проходят'],
            ['Т-07', 'Ручная блокировка',
             'POST /waf/api/block-ip/ {"ip": "1.2.3.4"}',
             'IP блокируется, HTTP 403 при следующем запросе'],
            ['Т-08', 'Ручная разблокировка',
             'POST /waf/api/unblock-ip/ {"ip": "1.2.3.4"}',
             'IP разблокирован, запросы проходят'],
            ['Т-09', 'Статистика API',
             'GET /waf/api/stats/',
             'JSON с корректными счётчиками'],
            ['Т-10', 'Симулятор атаки',
             'POST /waf/api/simulate/ {"count": 70}',
             'Атака обнаружена, IP заблокирован'],
            ['Т-11', 'HTML дашборд',
             'GET /waf/',
             'HTTP 200, страница отображается с Chart.js'],
            ['Т-12', 'Очистка логов',
             'POST /waf/api/clear-logs/',
             'Все таблицы очищены, трекеры сброшены'],
        ], col_widths=[1.2, 3.8, 5.5, 7])

    add_heading(doc, '6 Методы испытаний', 2)
    add_paragraph(doc,
        'Испытания проводятся методом «чёрного ящика» (функциональное тестирование). '
        'Инструменты: curl, HTTP-клиент браузера, встроенный симулятор атаки '
        'на дашборде /waf/.',
        indent=True)
    add_paragraph(doc, 'Методика проведения теста Т-01:', indent=True)
    steps = [
        'Запустить WAF-сервер: python manage.py runserver 0.0.0.0:8000',
        'Убедиться что mode: block в waf_config.yaml',
        'Выполнить POST /waf/api/simulate/ с телом {"count": 60}',
        'Проверить GET /waf/api/stats/ — поле active_blocks должно быть ≥ 1',
        'Выполнить GET /waf/api/events/?type=attack_detected — событие должно присутствовать',
        'Выполнить запрос от заблокированного IP — ожидать HTTP 403',
    ]
    for i, s in enumerate(steps, 1):
        add_bullet(doc, f'{i}. {s}')

    add_paragraph(doc)
    add_paragraph(doc,
        'Критерий успешного прохождения испытаний: '
        'все тесты Т-01 — Т-12 дают ожидаемые результаты. '
        'При отклонении результата от ожидаемого — тест считается проваленным, '
        'требуется анализ и устранение дефекта.',
        indent=True)
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 7: РУКОВОДСТВО ОПЕРАТОРА (ГОСТ 19.505-79)
# ─────────────────────────────────────────────────────────────────────────────
def write_operator_guide(doc):
    title_page(doc, 'XXXXXX.XXXXXX.ЭД3', 'РУКОВОДСТВО ОПЕРАТОРА')
    add_heading(doc, 'РУКОВОДСТВО ОПЕРАТОРА', 1, center=True)
    add_paragraph(doc, 'WAF-контейнер защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)

    add_heading(doc, '1 Назначение программы', 2)
    add_paragraph(doc,
        'WAF-контейнер предназначен для автоматической защиты веб-приложений от '
        'атак форсированного веб-браузинга. Программа перехватывает HTTP-запросы, '
        'анализирует активность IP-адресов и блокирует подозрительных клиентов.',
        indent=True)

    add_heading(doc, '2 Условия выполнения программы', 2)
    add_table(doc,
        ['Параметр', 'Требование'],
        [
            ['ОС', 'Linux / Windows / macOS'],
            ['Python', '3.11 и выше'],
            ['ОЗУ', 'Не менее 256 МБ'],
            ['Диск', 'Не менее 500 МБ'],
            ['Сеть', 'Порт 8000 должен быть свободен'],
            ['Зависимости', 'Django 4.2, requests, PyYAML, whitenoise'],
        ], col_widths=[5, 12.5])

    add_heading(doc, '3 Выполнение программы', 2)

    add_heading(doc, '3.1 Установка и первый запуск', 3)
    cmds = [
        ('Переход в директорию', 'cd artifacts/waf-container'),
        ('Установка зависимостей', 'pip install -r requirements.txt'),
        ('Применение миграций', 'python manage.py migrate'),
        ('Загрузка демо-данных', 'python manage.py seed_demo'),
        ('Запуск сервера', 'python manage.py runserver 0.0.0.0:8000'),
    ]
    for desc, cmd in cmds:
        add_paragraph(doc, f'{desc}:', indent=True)
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(2.5)
        r = p.add_run(cmd)
        r.font.name = 'Courier New'; r.font.size = Pt(11)

    add_heading(doc, '3.2 Работа с дашбордом', 3)
    add_paragraph(doc, 'После запуска открыть в браузере: http://localhost:8000/waf/', indent=True)
    add_paragraph(doc, 'Дашборд содержит следующие разделы:', indent=True)
    add_bullet(doc, 'Карточки KPI: всего запросов, заблокировано, активных блокировок, событий.')
    add_bullet(doc, 'График трафика по часам (Chart.js, обновляется каждые 10 сек).')
    add_bullet(doc, 'Круговая диаграмма причин блокировок.')
    add_bullet(doc, 'Таблица последних событий безопасности.')
    add_bullet(doc, 'Таблица активных блокировок с кнопкой «Разблокировать».')
    add_bullet(doc, 'Кнопка «Симулировать атаку» для демонстрации работы WAF.')

    add_heading(doc, '3.3 Управление режимом работы', 3)
    add_paragraph(doc,
        'Режим работы изменяется в файле config/waf_config.yaml, '
        'параметр mode. После изменения требуется перезапуск сервера.',
        indent=True)
    add_table(doc,
        ['Режим', 'Значение в YAML', 'Поведение'],
        [
            ['Блокировка', 'mode: block', 'IP блокируется при атаке (режим production)'],
            ['Мониторинг', 'mode: monitoring', 'Атака фиксируется, трафик не блокируется'],
            ['Отключён', 'mode: disabled', 'WAF прозрачен, все запросы пропускаются'],
        ], col_widths=[3.5, 4.5, 9.5])

    add_heading(doc, '3.4 Управление блокировками', 3)
    add_paragraph(doc, 'Ручная блокировка через дашборд:', indent=True)
    add_bullet(doc, 'На дашборде /waf/ в разделе «Управление» ввести IP и нажать «Заблокировать».')
    add_paragraph(doc, 'Ручная блокировка через API:', indent=True)
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(2.5)
    r = p.add_run('curl -X POST http://localhost:8000/waf/api/block-ip/ \\\n  -H "Content-Type: application/json" \\\n  -d \'{"ip": "1.2.3.4", "duration": 3600}\'')
    r.font.name = 'Courier New'; r.font.size = Pt(10)

    add_heading(doc, '3.5 Настройка пороговых значений', 3)
    add_paragraph(doc,
        'Откройте файл config/waf_config.yaml и измените нужные параметры. '
        'Перезапустите сервер для применения изменений.',
        indent=True)
    add_table(doc,
        ['Параметр', 'По умолчанию', 'Рекомендуемый диапазон'],
        [
            ['unique_urls', '50', '20–100 (меньше = чувствительнее)'],
            ['error_rate_percent', '70', '50–90'],
            ['rps', '30', '10–100'],
            ['window_seconds', '60', '30–300'],
            ['block_duration_seconds', '3600', '600–86400'],
        ], col_widths=[5, 4, 8.5])

    add_heading(doc, '4 Сообщения оператору', 2)
    add_table(doc,
        ['Сообщение / ситуация', 'Причина', 'Действие оператора'],
        [
            ['Страница /waf/ недоступна (ERR_CONNECTION)', 'Сервер не запущен',
             'Выполнить: python manage.py runserver 0.0.0.0:8000'],
            ['HTTP 500 при открытии /waf/', 'Ошибка миграций',
             'Выполнить: python manage.py migrate'],
            ['Активных блокировок 0 после симуляции', 'Режим monitoring или disabled',
             'Проверить mode в waf_config.yaml'],
            ['IP не блокируется несмотря на атаку', 'IP в whitelist',
             'Проверить раздел whitelist в waf_config.yaml'],
            ['Bad Gateway 502', 'Backend недоступен',
             'Проверить backend_url в waf_config.yaml или оставить пустым для demo-режима'],
            ['Лог не пишется в security_events.json', 'Нет прав на папку logs/',
             'Выполнить: mkdir -p logs && chmod 755 logs'],
        ], col_widths=[5, 4.5, 8])
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 8: РУКОВОДСТВО ПРОГРАММИСТА (ГОСТ 19.504-79)
# ─────────────────────────────────────────────────────────────────────────────
def write_programmer_guide(doc):
    title_page(doc, 'XXXXXX.XXXXXX.ЭД4', 'РУКОВОДСТВО ПРОГРАММИСТА')
    add_heading(doc, 'РУКОВОДСТВО ПРОГРАММИСТА', 1, center=True)
    add_paragraph(doc, 'WAF-контейнер защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)

    add_heading(doc, '1 Назначение и условия применения программ', 2)
    add_paragraph(doc,
        'WAF-контейнер — Django-приложение, реализующее защиту от атак форсированного '
        'веб-браузинга. Программа работает как Django middleware в WSGI-окружении. '
        'Требуется Python 3.11+, Django 4.2+.',
        indent=True)
    add_paragraph(doc, 'Условия применения:', indent=True)
    add_bullet(doc, 'ОЗУ: не менее 256 МБ (рекомендуется 512 МБ при > 1000 активных IP).')
    add_bullet(doc, 'Потоковое WSGI-окружение (gunicorn, uWSGI, встроенный dev-сервер Django).')
    add_bullet(doc, 'Запись в файловую систему: папки logs/ и sqlite-файл должны быть доступны.')

    add_heading(doc, '2 Характеристика программы', 2)
    add_table(doc,
        ['Характеристика', 'Значение'],
        [
            ['Архитектура', 'Django Middleware + Singleton ProtectionEngine'],
            ['Потокобезопасность', 'threading.Lock на каждый IPTracker'],
            ['Хранение состояния', 'In-memory (dict + deque) + SQLite (персистентность)'],
            ['Временна́я сложность check_and_record', 'O(n) по длине окна (deque.popleft)'],
            ['Пространственная сложность', 'O(U × IP) где U — уникальных URL, IP — активных IP'],
            ['Фоновая очистка', 'daemon-поток каждые 300 секунд'],
            ['Автообновление дашборда', 'JavaScript fetch каждые 10 секунд'],
        ], col_widths=[6, 11.5])

    add_heading(doc, '3 Обращение к программе', 2)
    add_paragraph(doc, 'Точка входа в Django — settings.py, раздел MIDDLEWARE:', indent=True)
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(2)
    r = p.add_run("MIDDLEWARE = [\n    ...\n    'waf.middleware.ForcedBrowsingProtectionMiddleware',\n]")
    r.font.name = 'Courier New'; r.font.size = Pt(10)

    add_paragraph(doc, 'Получение экземпляра движка из любого модуля:', indent=True)
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(2)
    r = p.add_run("from waf.protection import ProtectionEngine\nengine = ProtectionEngine.get_instance()")
    r.font.name = 'Courier New'; r.font.size = Pt(10)

    add_heading(doc, '4 Входные и выходные данные', 2)
    add_paragraph(doc, 'Входные данные ProtectionEngine.check_and_record():', indent=True)
    add_table(doc,
        ['Параметр', 'Тип', 'Описание'],
        [
            ['ip', 'str', 'IP-адрес клиента (IPv4 или IPv6)'],
            ['url', 'str', 'Полный URL запроса (включая query string)'],
            ['path', 'str', 'Путь URL без query string'],
            ['method', 'str', 'HTTP-метод: GET, POST, PUT и т.д.'],
            ['status_code', 'int | None', 'HTTP-статус ответа (None если заблокирован до backend)'],
            ['user_agent', 'str', 'User-Agent заголовок клиента'],
        ], col_widths=[4, 3, 10.5])

    add_paragraph(doc, 'Возвращаемое значение (dict):', indent=True)
    add_table(doc,
        ['Поле', 'Тип', 'Значения / Описание'],
        [
            ['action', 'str', 'allow | block | monitor | warn | whitelist'],
            ['reason', 'str | None', 'unique_url_limit | error_rate_limit | rps_limit | None'],
            ['stats', 'dict', 'unique_urls, total_requests, error_404_count, error_rate'],
        ], col_widths=[3.5, 3, 11])

    add_heading(doc, '5 REST API — справочник эндпоинтов', 2)
    add_table(doc,
        ['Метод', 'URL', 'Описание', 'Тело / Параметры'],
        [
            ['GET', '/waf/', 'HTML-дашборд', '—'],
            ['GET', '/waf/api/stats/', 'Сводная статистика', '—'],
            ['GET', '/waf/api/events/', 'Список событий', '?limit=50&type=attack_detected'],
            ['GET', '/waf/api/config/', 'Текущий конфиг WAF', '—'],
            ['POST', '/waf/api/block-ip/', 'Ручная блокировка', '{"ip","duration","reason"}'],
            ['POST', '/waf/api/unblock-ip/', 'Разблокировка', '{"ip"}'],
            ['POST', '/waf/api/simulate/', 'Симуляция атаки', '{"ip","count"}'],
            ['POST', '/waf/api/clear-logs/', 'Очистка всех данных', '—'],
        ], col_widths=[2, 4.5, 5, 6])

    add_heading(doc, '6 Расширение и доработка', 2)
    add_paragraph(doc, 'Добавление нового порогового критерия:', indent=True)
    steps = [
        'Добавить параметр в DEFAULT_CONFIG["thresholds"] в protection.py.',
        'Добавить чтение параметра из waf_config.yaml.',
        'Добавить условие проверки в метод check_and_record() после строки с rps_limit.',
        'Добавить новое значение в BLOCK_REASON_CHOICES в models.py.',
        'Выполнить: python manage.py makemigrations waf && python manage.py migrate.',
    ]
    for s in steps:
        add_bullet(doc, s)

    add_paragraph(doc, 'Замена SQLite на PostgreSQL:', indent=True)
    add_bullet(doc, 'В settings.py заменить ENGINE на django.db.backends.postgresql.')
    add_bullet(doc, 'Указать DATABASE_URL в переменных окружения.')
    add_bullet(doc, 'Выполнить миграции на новой БД.')
    add_bullet(doc, 'Для in-memory счётчиков рассмотреть Redis + django-redis-cache.')

    add_heading(doc, '7 Сообщения программисту', 2)
    add_table(doc,
        ['Сообщение в логе', 'Причина', 'Действие'],
        [
            ['ProtectionEngine инициализирован', 'Штатный запуск', 'Ничего не требуется'],
            ['Конфиг загружен из ...yaml', 'Конфиг прочитан', 'Ничего не требуется'],
            ['Ошибка загрузки конфига', 'YAML не парсится', 'Проверить синтаксис waf_config.yaml'],
            ['Ошибка блокировки IP', 'Ошибка записи в БД', 'Проверить доступность db.sqlite3'],
            ['Ошибка записи лога запроса', 'Ошибка записи в БД', 'Проверить доступность db.sqlite3'],
            ['Proxy error for ...', 'Backend недоступен', 'Проверить backend_url или оставить пустым'],
        ], col_widths=[5, 4.5, 8])
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ДОКУМЕНТ 9: ФОРМУЛЯР (ГОСТ 19.501-78)
# ─────────────────────────────────────────────────────────────────────────────
def write_formular(doc):
    title_page(doc, 'XXXXXX.XXXXXX.ЭД2', 'ФОРМУЛЯР')
    add_heading(doc, 'ФОРМУЛЯР', 1, center=True)
    add_paragraph(doc, 'WAF-контейнер защиты от атаки «Форсированного веб-браузинга»', center=True)
    add_paragraph(doc)

    add_heading(doc, '1 Общие указания', 2)
    add_paragraph(doc,
        'Перед эксплуатацией программного изделия необходимо внимательно '
        'ознакомиться с «Руководством оператора» (XXXXXX.XXXXXX.ЭД3) и '
        '«Руководством программиста» (XXXXXX.XXXXXX.ЭД4). '
        'Формуляр должен находиться у лица, ответственного за эксплуатацию.',
        indent=True)

    add_heading(doc, '2 Общие сведения', 2)
    add_table(doc,
        ['Параметр', 'Значение'],
        [
            ['Наименование', 'WAF-контейнер защиты от форсированного веб-браузинга'],
            ['Обозначение', 'XXXXXX.XXXXXX'],
            ['Разработчик', 'Вотинцева А.С.'],
            ['Версия', '1.0.0'],
            ['Дата разработки', datetime.date.today().strftime('%d.%m.%Y')],
            ['Язык', 'Python 3.11 / Django 4.2'],
            ['Назначение', 'Защита от УБИ.159 (форсированный веб-браузинг)'],
        ], col_widths=[6, 11.5])

    add_heading(doc, '3 Основные характеристики', 2)
    add_table(doc,
        ['Характеристика', 'Значение'],
        [
            ['Макс. отслеживаемых IP', 'Не ограничено (ограничено ОЗУ)'],
            ['Размер скользящего окна', '60 секунд (настраиваемо)'],
            ['Порог уникальных URL', '50 (настраиваемо)'],
            ['Порог ошибок 404', '70% (настраиваемо)'],
            ['Порог RPS', '30 (настраиваемо)'],
            ['Время блокировки', '3600 сек = 1 час (настраиваемо)'],
            ['Режимы', 'block / monitoring / disabled'],
            ['Порт по умолчанию', '8000'],
            ['Дашборд', 'http://localhost:8000/waf/'],
            ['Django Admin', 'http://localhost:8000/admin/ (admin/admin123)'],
        ], col_widths=[6, 11.5])

    add_heading(doc, '4 Комплектность', 2)
    add_table(doc,
        ['Обозначение', 'Наименование', 'Кол-во'],
        [
            ['XXXXXX.XXXXXX.001', 'Спецификация', '1'],
            ['XXXXXX.XXXXXX.002', 'Техническое задание', '1'],
            ['XXXXXX.XXXXXX.003', 'Текст программы', '1'],
            ['XXXXXX.XXXXXX.004', 'Описание программы', '1'],
            ['XXXXXX.XXXXXX.005', 'Пояснительная записка', '1'],
            ['XXXXXX.XXXXXX.006', 'Программа и методика испытаний', '1'],
            ['XXXXXX.XXXXXX.ЭД2', 'Формуляр', '1'],
            ['XXXXXX.XXXXXX.ЭД3', 'Руководство оператора', '1'],
            ['XXXXXX.XXXXXX.ЭД4', 'Руководство программиста', '1'],
        ], col_widths=[5, 10, 2.5])

    add_heading(doc, '5 Периодический контроль основных характеристик', 2)
    add_table(doc,
        ['Характеристика', 'Периодичность контроля', 'Метод'],
        [
            ['Доступность дашборда /waf/', 'Ежедневно', 'HTTP GET, ожидать 200 OK'],
            ['Запись событий в JSON-лог', 'Еженедельно', 'Проверить logs/security_events.json'],
            ['Количество активных блокировок', 'Ежедневно', 'GET /waf/api/stats/'],
            ['Размер файла db.sqlite3', 'Ежемесячно', 'ls -lh db.sqlite3, при > 1 ГБ — очистка'],
            ['Корректность порогов', 'При изменении трафика', 'Анализ статистики дашборда'],
        ], col_widths=[5.5, 4, 8])

    add_heading(doc, '6 Свидетельство о приёмке', 2)
    add_paragraph(doc,
        'WAF-контейнер защиты от атаки форсированного веб-браузинга, '
        'обозначение XXXXXX.XXXXXX, прошёл испытания согласно '
        '«Программе и методике испытаний» (XXXXXX.XXXXXX.006) '
        'и признан годным к эксплуатации.',
        indent=True)
    add_table(doc,
        ['', ''],
        [
            ['Разработчик', 'Вотинцева А.С. ____________'],
            ['Дата приёмки', datetime.date.today().strftime('%d.%m.%Y')],
        ], col_widths=[5, 12.5])

    add_heading(doc, '7 Гарантийные обязательства', 2)
    add_paragraph(doc,
        'Разработчик гарантирует соответствие программного изделия требованиям '
        'технического задания при соблюдении условий эксплуатации, '
        'изложенных в «Руководстве оператора».',
        indent=True)

    add_heading(doc, '8 Сведения об изменениях', 2)
    add_table(doc,
        ['№', 'Дата', 'Содержание изменения', 'Ответственный'],
        [
            ['1', datetime.date.today().strftime('%d.%m.%Y'),
             'Первоначальная разработка WAF-контейнера v1.0', 'Вотинцева А.С.'],
        ], col_widths=[1, 3, 11, 4])
    add_page_break(doc)


# ─────────────────────────────────────────────────────────────────────────────
# ГЛАВНАЯ ФУНКЦИЯ — СБОРКА ДОКУМЕНТА
# ─────────────────────────────────────────────────────────────────────────────
def generate_espd():
    doc = Document()
    set_margins(doc)

    # Настройка стилей документа
    style = doc.styles['Normal']
    style.font.name = 'Times New Roman'
    style.font.size = Pt(12)

    # ─── ТИТУЛЬНЫЙ ЛИСТ ВСЕГО ПАКЕТА ────────────────────────────────────────
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run('ПАКЕТ ПРОГРАММНОЙ ДОКУМЕНТАЦИИ (ЕСПД)')
    set_font(r, size=18, bold=True)
    add_paragraph(doc)
    p2 = doc.add_paragraph()
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r2 = p2.add_run('WAF-КОНТЕЙНЕР')
    set_font(r2, size=16, bold=True)
    p3 = doc.add_paragraph()
    p3.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r3 = p3.add_run('Защита от атаки «Форсированного веб-браузинга» (УБИ.159)')
    set_font(r3, size=14)
    add_paragraph(doc)
    add_paragraph(doc, 'Аналог Wallarm Forced Browsing Protection', center=True, italic=True)
    add_paragraph(doc)
    add_paragraph(doc)

    add_paragraph(doc, 'Состав пакета документации:', center=False, bold=True)
    docs_list = [
        ('XXXXXX.XXXXXX.001', 'Спецификация', 'ГОСТ 19.202-78'),
        ('XXXXXX.XXXXXX.002', 'Техническое задание', 'ГОСТ 19.201-78'),
        ('XXXXXX.XXXXXX.003', 'Текст программы', 'ГОСТ 19.401-78'),
        ('XXXXXX.XXXXXX.004', 'Описание программы', 'ГОСТ 19.402-78'),
        ('XXXXXX.XXXXXX.005', 'Пояснительная записка', 'ГОСТ 19.404-79'),
        ('XXXXXX.XXXXXX.006', 'Программа и методика испытаний', 'ГОСТ 19.301-79'),
        ('XXXXXX.XXXXXX.ЭД2', 'Формуляр', 'ГОСТ 19.501-78'),
        ('XXXXXX.XXXXXX.ЭД3', 'Руководство оператора', 'ГОСТ 19.505-79'),
        ('XXXXXX.XXXXXX.ЭД4', 'Руководство программиста', 'ГОСТ 19.504-79'),
    ]
    add_table(doc, ['Обозначение', 'Наименование документа', 'Стандарт'],
              docs_list, col_widths=[5, 8, 4.5])
    add_paragraph(doc)
    add_paragraph(doc)
    add_paragraph(doc, f'Разработчик: Вотинцева А.С.', center=True)
    add_paragraph(doc, f'Дата: {datetime.date.today().strftime("%d.%m.%Y")}', center=True)
    add_page_break(doc)

    # ─── СБОРКА ДОКУМЕНТОВ ──────────────────────────────────────────────────
    print('Generating: Спецификация...')
    write_specification(doc)
    print('Generating: Техническое задание...')
    write_tz(doc)
    print('Generating: Текст программы...')
    write_text_program(doc)
    print('Generating: Описание программы...')
    write_description(doc)
    print('Generating: Пояснительная записка...')
    write_explanatory_note(doc)
    print('Generating: Программа и методика испытаний...')
    write_test_program(doc)
    print('Generating: Руководство оператора...')
    write_operator_guide(doc)
    print('Generating: Руководство программиста...')
    write_programmer_guide(doc)
    print('Generating: Формуляр...')
    write_formular(doc)

    out_path = '/home/runner/workspace/ЕСПД_WAF_Контейнер.docx'
    doc.save(out_path)
    print(f'\nДокумент сохранён: {out_path}')
    return out_path


if __name__ == '__main__':
    generate_espd()
