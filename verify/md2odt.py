#!/usr/bin/env python3
"""
auth_log.md -> auth_log.odt

Вёрстку делает LibreOffice: скрипт готовит HTML с CSS и передаёт его
конвертеру soffice. Так таблицы, шрифты и интервалы получаются
правильными, а не «на глаз» в сыром ODF.

Раньше ODF собирался напрямую, и это давало плохой результат: без
<table:table-column> LibreOffice схлопывал колонки таблиц, а шрифты
и интервалы выглядели случайно. Ставить пакеты на хосте не нужно -
конвертер запускается там, где есть LibreOffice.

Запуск:
    python3 verify/md2odt.py вход.md выход.odt
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

CSS = """
@page { size: A4 portrait; margin: 1.8cm 1.5cm 1.8cm 2cm; }
body { font-family: "Liberation Sans", "DejaVu Sans", sans-serif;
       font-size: 11pt; line-height: 1.35; }
h1 { font-size: 20pt; color: #1a1a1a; margin-bottom: 0.2cm;
     border-bottom: 2px solid #4472c4; padding-bottom: 0.1cm; }
h2 { font-size: 15pt; color: #2a4a7a; margin-top: 0.6cm;
     margin-bottom: 0.2cm; }
h3 { font-size: 12.5pt; color: #2a4a7a; margin-top: 0.45cm;
     margin-bottom: 0.15cm; }
p  { margin-top: 0cm; margin-bottom: 0.15cm; text-align: left; }
code { font-family: "Liberation Mono", monospace; font-size: 9.5pt;
       background-color: #f0f2f5; color: #a03050; }
pre { font-family: "Liberation Mono", monospace; font-size: 9pt;
      background-color: #f4f6f8; border: 1px solid #d0d7de;
      padding: 0.25cm; margin-top: 0.15cm; margin-bottom: 0.25cm;
      white-space: pre-wrap; }
pre code { background-color: transparent; color: #24292f; font-size: 9pt; }
table { border-collapse: collapse; width: 100%;
        margin-top: 0.2cm; margin-bottom: 0.3cm; }
th { background-color: #dce6f1; border: 1px solid #8ba3c7;
     padding: 0.12cm 0.15cm; text-align: left; font-weight: bold; }
td { border: 1px solid #b8c4d4; padding: 0.12cm 0.15cm;
     vertical-align: top; }
blockquote { border-left: 3px solid #4472c4; background-color: #f2f6fb;
             margin-left: 0cm; margin-right: 0.4cm;
             padding: 0.12cm 0.3cm; color: #33475b; }
hr { border: none; border-top: 1px solid #c8d0da; margin: 0.25cm 0; }
ul { margin-top: 0cm; margin-bottom: 0.2cm; }
"""

TPL = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>{css}</style></head><body>
{body}
</body></html>"""


def esc(t):
    return (t.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))


def inline(text):
    """Строчная разметка. Обратные кавычки -> <code>, **жирный** -> <b>."""
    out, pos = [], 0
    for m in re.finditer(r'\*\*(.+?)\*\*|`([^`]+)`', text):
        out.append(esc(text[pos:m.start()]))
        if m.group(1) is not None:
            out.append('<b>%s</b>' % esc(m.group(1)))
        else:
            out.append('<code>%s</code>' % esc(m.group(2)))
        pos = m.end()
    out.append(esc(text[pos:]))
    return ''.join(out)


def split_row(line):
    line = line.strip().strip('|')
    return [c.strip() for c in line.split('|')]


def is_sep(line):
    s = line.strip()
    return s.startswith('|') and bool(re.match(r'^\|[\s:\-|]+\|$', s))


def align_of(cell):
    left, right = cell.startswith(':'), cell.endswith(':')
    if left and right:
        return 'center'
    if right:
        return 'right'
    return 'left'


def render_table(rows, aligns):
    # Импортёр HTML в LibreOffice игнорирует border-collapse и часть
    # CSS-свойств таблиц, поэтому рамки и заливку задаём атрибутами
    # border/bgcolor - их он понимает однозначно.
    out = ['<table border="1" cellspacing="0" cellpadding="4" width="100%">']
    for r, cells in enumerate(rows):
        out.append('<tr>')
        for c, cell in enumerate(cells):
            al = aligns[c] if c < len(aligns) else 'left'
            if r == 0:
                out.append('<th bgcolor="#dce6f1" style="text-align:%s;'
                           'border:1px solid #8ba3c7">%s</th>'
                           % (al, inline(cell)))
            else:
                out.append('<td style="text-align:%s;'
                           'border:1px solid #b8c4d4">%s</td>'
                           % (al, inline(cell)))
        out.append('</tr>')
    out.append('</table>')
    return ''.join(out)


def md2html(md):
    lines = md.split('\n')
    out, i, n = [], 0, len(lines)
    while i < n:
        line = lines[i]

        if line.startswith('```'):
            i += 1
            buf = []
            while i < n and not lines[i].startswith('```'):
                buf.append(esc(lines[i]))
                i += 1
            i += 1
            out.append('<pre>%s</pre>' % '\n'.join(buf))
            continue

        if re.match(r'^-{3,}$', line.strip()):
            out.append('<hr/>')
            i += 1
            continue

        if line.strip().startswith('|') and i + 1 < n and is_sep(lines[i + 1]):
            aligns = [align_of(c) for c in split_row(lines[i + 1])]
            rows = [split_row(line)]
            i += 2
            while i < n and lines[i].strip().startswith('|'):
                rows.append(split_row(lines[i]))
                i += 1
            out.append(render_table(rows, aligns))
            continue

        m = re.match(r'^(#{1,4})\s+(.*)$', line)
        if m:
            lvl = min(len(m.group(1)), 4)
            out.append('<h%d>%s</h%d>' % (lvl, inline(m.group(2)), lvl))
            i += 1
            continue

        if line.startswith('>'):
            buf = []
            while i < n and lines[i].startswith('>'):
                buf.append(inline(lines[i].lstrip('> ')))
                i += 1
            out.append('<blockquote>%s</blockquote>' % '<br/>'.join(buf))
            continue

        if re.match(r'^\s*[-*]\s+', line):
            out.append('<ul>')
            while i < n and re.match(r'^\s*[-*]\s+', lines[i]):
                out.append('<li>%s</li>'
                           % inline(re.sub(r'^\s*[-*]\s+', '', lines[i])))
                i += 1
            out.append('</ul>')
            continue

        if not line.strip():
            i += 1
            continue

        out.append('<p>%s</p>' % inline(line))
        i += 1

    return '\n'.join(out)


def soffice():
    for c in ('soffice', 'libreoffice'):
        p = shutil.which(c)
        if p:
            return p
    return None


A4_WIDTH = '21.0cm'
A4_HEIGHT = '29.7cm'


def force_a4(odt_path):
    """Проставляет формат бумаги A4.

    Директива `@page { size: A4 }` из HTML импортёр LibreOffice
    игнорирует, и документ выходит на Letter. Поэтому размер
    страницы задаётся правкой styles.xml в готовом .odt.
    """
    src = zipfile.ZipFile(odt_path)
    tmp_odt = tempfile.NamedTemporaryFile(suffix='.odt', delete=False)
    tmp_odt.close()
    try:
        with zipfile.ZipFile(tmp_odt.name, 'w') as z:
            for info in src.infolist():
                data = src.read(info.filename)
                if info.filename == 'styles.xml':
                    s = data.decode('utf-8')
                    s = re.sub(r'fo:page-width="[^"]*"',
                               'fo:page-width="%s"' % A4_WIDTH, s)
                    s = re.sub(r'fo:page-height="[^"]*"',
                               'fo:page-height="%s"' % A4_HEIGHT, s)
                    data = s.encode('utf-8')
                if info.filename == 'mimetype':
                    zi = zipfile.ZipInfo('mimetype')
                    zi.compress_type = zipfile.ZIP_STORED
                    z.writestr(zi, data)
                else:
                    z.writestr(info, data, zipfile.ZIP_DEFLATED)
        shutil.copy(tmp_odt.name, odt_path)
    finally:
        src.close()
        os.unlink(tmp_odt.name)


def convert(md_path, odt_path):
    with open(md_path) as f:
        md = f.read()
    title = next((l.lstrip('# ').strip() for l in md.split('\n')
                  if l.startswith('# ')), 'Документ')
    html = TPL.format(title=esc(title), css=CSS, body=md2html(md))

    tmp = tempfile.mkdtemp(prefix='md2odt.')
    try:
        src = os.path.join(tmp, 'doc.html')
        with open(src, 'w') as f:
            f.write(html)

        exe = soffice()
        if not exe:
            sys.exit('LibreOffice не найден: нужен soffice или libreoffice')
        cmd = [exe, '--headless',
               # Без --infilter LibreOffice загружает HTML как документ
               # Writer/Web: он открывается как веб-страница - весь текст
               # на одной бесконечной полосе, без разбивки на страницы.
               # "HTML (StarWriter)" заставляет грузить HTML в обычный
               # текстовый Writer, и уже он сохраняется в .odt.
               '--infilter=HTML (StarWriter)',
               '--convert-to', 'odt:writer8', '--outdir', tmp, src]
        # subprocess.run() появился только в Python 3.5, а на целевой
        # системе (Ubuntu 15.10) стоит 3.4 - поэтому Popen
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out = proc.communicate()[0]
        made = os.path.join(tmp, 'doc.odt')
        if not os.path.exists(made):
            sys.exit('конвертация не удалась:\n'
                     + out.decode('utf-8', 'replace'))
        shutil.copy(made, odt_path)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    force_a4(odt_path)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('Запуск: python3 verify/md2odt.py вход.md выход.odt')
    convert(sys.argv[1], sys.argv[2])
    print('записано: %s' % sys.argv[2])