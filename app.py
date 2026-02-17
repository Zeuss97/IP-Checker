from __future__ import annotations

import html
import ipaddress
import os
import platform
import socket
import sqlite3
import subprocess
import threading
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DB_PATH = Path(os.environ.get("IP_REGISTRY_DB", "ips.db"))
PING_INTERVAL_SECONDS = 12 * 60 * 60
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "5000"))

HOST_TYPE_OPTIONS = ["NOTEBOOK", "DESKTOP", "SERVER", "IMPRESORA", "ROUTER", "OTRO"]

_db_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _db_lock, closing(get_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                alias TEXT,
                host_name TEXT,
                host_type TEXT,
                location TEXT,
                notes TEXT,
                hostname TEXT,
                last_ping_at TEXT,
                last_status TEXT,
                last_output TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        _ensure_columns(conn)
        conn.commit()


def _ensure_columns(conn: sqlite3.Connection) -> None:
    current = {row["name"] for row in conn.execute("PRAGMA table_info(ip_registry)").fetchall()}
    missing = {
        "host_name": "ALTER TABLE ip_registry ADD COLUMN host_name TEXT",
        "host_type": "ALTER TABLE ip_registry ADD COLUMN host_type TEXT",
        "location": "ALTER TABLE ip_registry ADD COLUMN location TEXT",
        "notes": "ALTER TABLE ip_registry ADD COLUMN notes TEXT",
    }
    for column, statement in missing.items():
        if column not in current:
            conn.execute(statement)


def is_valid_ip(ip_value: str) -> bool:
    try:
        ipaddress.ip_address(ip_value.strip())
    except ValueError:
        return False
    return True


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def register_ip(ip_address: str, alias: str | None = None) -> tuple[bool, str]:
    clean_ip = ip_address.strip()
    if not is_valid_ip(clean_ip):
        return False, "La IP no es válida"

    with _db_lock, closing(get_connection()) as conn:
        try:
            conn.execute(
                "INSERT INTO ip_registry (ip_address, alias, created_at) VALUES (?, ?, ?)",
                (clean_ip, alias.strip() if alias else None, _now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return False, "La IP ya estaba registrada"
    return True, "IP registrada correctamente"


def update_host_details(
    ip_address: str,
    host_name: str,
    host_type: str,
    location: str,
    notes: str,
    alias: str,
) -> tuple[bool, str]:
    if host_type and host_type not in HOST_TYPE_OPTIONS:
        return False, "Tipo de host inválido"

    with _db_lock, closing(get_connection()) as conn:
        row = conn.execute("SELECT id FROM ip_registry WHERE ip_address = ?", (ip_address,)).fetchone()
        if row is None:
            return False, "No existe la IP indicada"

        conn.execute(
            """
            UPDATE ip_registry
            SET alias = ?, host_name = ?, host_type = ?, location = ?, notes = ?
            WHERE ip_address = ?
            """,
            (
                alias.strip() or None,
                host_name.strip() or None,
                host_type.strip() or None,
                location.strip() or None,
                notes.strip() or None,
                ip_address,
            ),
        )
        conn.commit()
    return True, "Host actualizado"


def resolve_hostname(ip_address: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def run_ping(ip_address: str) -> tuple[str, str]:
    system = platform.system().lower()
    cmd = ["ping", "-n", "1", "-a", ip_address] if system == "windows" else ["ping", "-c", "1", ip_address]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        return "OK", output.strip()
    return "ERROR", output.strip() or f"Ping fallido con código {proc.returncode}"


def ping_all_registered_ips() -> None:
    with _db_lock, closing(get_connection()) as conn:
        rows = conn.execute("SELECT id, ip_address FROM ip_registry").fetchall()

    for row in rows:
        ip_address = row["ip_address"]
        hostname = resolve_hostname(ip_address)
        status, output = run_ping(ip_address)
        with _db_lock, closing(get_connection()) as conn:
            conn.execute(
                """
                UPDATE ip_registry
                SET hostname = ?, last_ping_at = ?, last_status = ?, last_output = ?
                WHERE id = ?
                """,
                (hostname, _now_iso(), status, output, row["id"]),
            )
            conn.commit()


def infer_segment_24(ip_address: str) -> str:
    parsed_ip = ipaddress.ip_address(ip_address)
    if parsed_ip.version != 4:
        return "IPv6"
    return str(ipaddress.ip_network(f"{ip_address}/24", strict=False))


def normalize_segment_filter(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    value = raw_value.strip()
    if not value:
        return None

    if value.endswith("/24") and "." not in value:
        octet = value.split("/")[0]
        if octet.isdigit() and 0 <= int(octet) <= 255:
            return f"THIRD_OCTET:{int(octet)}"

    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.version == 4 and network.prefixlen == 24:
            return str(network)
    except ValueError:
        return None

    return None


def get_rows(segment_filter: str | None = None) -> list[dict[str, str | None]]:
    with _db_lock, closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT ip_address, alias, host_name, host_type, location, notes, hostname, last_ping_at, last_status, last_output
            FROM ip_registry
            ORDER BY created_at DESC
            """
        ).fetchall()

    rendered_rows: list[dict[str, str | None]] = []
    for row in rows:
        segment = infer_segment_24(row["ip_address"])
        current = {
            "ip_address": row["ip_address"],
            "alias": row["alias"],
            "host_name": row["host_name"],
            "host_type": row["host_type"],
            "location": row["location"],
            "notes": row["notes"],
            "hostname": row["hostname"],
            "last_ping_at": row["last_ping_at"],
            "last_status": row["last_status"],
            "last_output": row["last_output"],
            "segment": segment,
        }

        if segment_filter:
            if segment_filter.startswith("THIRD_OCTET:"):
                if segment == "IPv6":
                    continue
                third_octet = int(row["ip_address"].split(".")[2])
                requested = int(segment_filter.split(":", maxsplit=1)[1])
                if third_octet != requested:
                    continue
            elif segment != segment_filter:
                continue

        rendered_rows.append(current)
    return rendered_rows


def get_ip_row(ip_address: str) -> dict[str, str | None] | None:
    with _db_lock, closing(get_connection()) as conn:
        row = conn.execute(
            """
            SELECT ip_address, alias, host_name, host_type, location, notes, hostname, last_ping_at, last_status, last_output
            FROM ip_registry WHERE ip_address = ?
            """,
            (ip_address,),
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def get_available_segments() -> list[str]:
    with _db_lock, closing(get_connection()) as conn:
        rows = conn.execute("SELECT ip_address FROM ip_registry").fetchall()
    return sorted({infer_segment_24(row["ip_address"]) for row in rows})


def _render_host_types(current: str | None) -> str:
    options = ['<option value="">-</option>']
    for item in HOST_TYPE_OPTIONS:
        selected = " selected" if current == item else ""
        options.append(f'<option value="{item}"{selected}>{item}</option>')
    return "".join(options)


def render_page(message: str = "", category: str = "success", segment_filter: str | None = None, raw_filter: str = "") -> str:
    rows = get_rows(segment_filter=segment_filter)
    segments = get_available_segments()
    alert = f'<p class="alert {category}">{html.escape(message)}</p>' if message else ""
    options = ['<option value="">Todos</option>']
    for seg in segments:
        selected = " selected" if segment_filter == seg else ""
        options.append(f'<option value="{html.escape(seg)}"{selected}>{html.escape(seg)}</option>')

    applied_badge = ""
    if segment_filter:
        human_filter = segment_filter.replace("THIRD_OCTET:", "tercer octeto ")
        applied_badge = f'<p class="filter-badge">Filtro aplicado: {html.escape(human_filter)}</p>'
    elif raw_filter:
        applied_badge = '<p class="alert error">Filtro inválido. Usa por ejemplo 192.168.56.0/24 o 56/24.</p>'

    lines = []
    for row in rows:
        details = (
            f"Nombre: {html.escape(row['host_name'] or '-')}<br>"
            f"Tipo: {html.escape(row['host_type'] or '-')}<br>"
            f"Ubicación: {html.escape(row['location'] or '-')}<br>"
            f"Alias: {html.escape(row['alias'] or '-')}"
        )
        lines.append(
            "<tr>"
            f"<td>{html.escape(row['segment'] or '-')}</td>"
            f"<td>{html.escape(row['ip_address'] or '-')}</td>"
            f"<td>{details}</td>"
            f"<td>{html.escape(row['hostname'] or '-')}</td>"
            f"<td>{html.escape(row['last_status'] or 'Sin ejecutar')}</td>"
            f"<td>{html.escape(row['last_ping_at'] or 'Nunca')}</td>"
            f"<td><pre>{html.escape(row['last_output'] or '-')}</pre></td>"
            f"<td><a class='btn-link' href='/edit?ip={html.escape(row['ip_address'] or '')}'>Editar host</a></td>"
            "</tr>"
        )

    body_rows = "".join(lines) if lines else '<tr><td colspan="8" class="empty">No hay IPs para el filtro seleccionado</td></tr>'
    return f"""<!doctype html>
<html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Registro de IPs</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head><body>
<main class=\"container\"><h1>Registro y monitoreo de IPs</h1>{alert}
<section class=\"panel\"><h2>Registrar IP</h2>
<form action=\"/register\" method=\"post\" class=\"form-grid\">
<label>Dirección IP<input type=\"text\" name=\"ip_address\" required></label>
<label>Alias (opcional)<input type=\"text\" name=\"alias\"></label>
<button type=\"submit\">Guardar</button></form></section>
<section class=\"panel\"><div class=\"panel-header\"><h2>IPs registradas</h2>
<form action=\"/ping-now\" method=\"post\"><button type=\"submit\">Ejecutar ping ahora</button></form></div>
<form action=\"/\" method=\"get\" class=\"filter-form\">
<label>Filtrar por segmento (/24)
<input type=\"text\" name=\"segment_text\" value=\"{html.escape(raw_filter)}\" placeholder=\"192.168.56.0/24 o 56/24\"></label>
<label>Segmentos detectados
<select name=\"segment_select\">{''.join(options)}</select></label>
<button type=\"submit\">Aplicar filtro</button>
<a href=\"/\" class=\"btn-link\">Limpiar</a>
</form>{applied_badge}
<table><thead><tr><th>Segmento</th><th>IP</th><th>Detalles host</th><th>Hostname (ping -a)</th><th>Último estado</th><th>Último ping</th><th>Salida</th><th>Acciones</th></tr></thead>
<tbody>{body_rows}</tbody></table></section></main></body></html>"""


def render_edit_page(ip_data: dict[str, str | None], message: str = "", category: str = "success") -> str:
    alert = f'<p class="alert {category}">{html.escape(message)}</p>' if message else ""
    return f"""<!doctype html>
<html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Modificar host</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head><body>
<main class=\"container\"><h1>MODIFICAR IP</h1>{alert}
<section class=\"panel edit-panel\">
<form action=\"/edit\" method=\"post\" class=\"form-grid\">
<label>IP
<input type=\"text\" name=\"ip_address\" value=\"{html.escape(ip_data['ip_address'] or '')}\" readonly></label>
<label>NOMBRE
<input type=\"text\" name=\"host_name\" value=\"{html.escape(ip_data['host_name'] or '')}\"></label>
<label>TIPO
<select name=\"host_type\">{_render_host_types(ip_data['host_type'])}</select></label>
<label>UBICACION
<input type=\"text\" name=\"location\" value=\"{html.escape(ip_data['location'] or '')}\"></label>
<label>ALIAS
<input type=\"text\" name=\"alias\" value=\"{html.escape(ip_data['alias'] or '')}\"></label>
<label>DETALLES ADICIONALES
<textarea name=\"notes\" rows=\"4\">{html.escape(ip_data['notes'] or '')}</textarea></label>
<div class=\"actions\">
<button type=\"submit\">MODIFICAR - ALTA</button>
<a href=\"/\" class=\"btn-link\">Volver</a>
</div>
</form>
</section></main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            query = parse_qs(parsed.query)
            text = query.get("segment_text", [""])[0].strip()
            pick = query.get("segment_select", [""])[0].strip()
            raw_filter = text or pick
            segment_filter = normalize_segment_filter(raw_filter)
            self._respond_html(render_page(segment_filter=segment_filter, raw_filter=raw_filter))
            return

        if parsed.path == "/edit":
            query = parse_qs(parsed.query)
            ip_address = query.get("ip", [""])[0]
            ip_data = get_ip_row(ip_address)
            if ip_data is None:
                self._respond_html(render_page("IP no encontrada", "error"))
            else:
                self._respond_html(render_edit_page(ip_data))
            return

        if parsed.path == "/static/style.css":
            css = Path("static/style.css").read_text(encoding="utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.end_headers()
            self.wfile.write(css.encode("utf-8"))
            return

        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw)

        if parsed.path == "/register":
            ip_address = form.get("ip_address", [""])[0]
            alias = form.get("alias", [""])[0]
            ok, msg = register_ip(ip_address, alias)
            self._respond_html(render_page(msg, "success" if ok else "error"))
            return

        if parsed.path == "/ping-now":
            ping_all_registered_ips()
            self._respond_html(render_page("Ping manual ejecutado", "success"))
            return

        if parsed.path == "/edit":
            ip_address = form.get("ip_address", [""])[0]
            host_name = form.get("host_name", [""])[0]
            host_type = form.get("host_type", [""])[0]
            location = form.get("location", [""])[0]
            notes = form.get("notes", [""])[0]
            alias = form.get("alias", [""])[0]
            ok, msg = update_host_details(ip_address, host_name, host_type, location, notes, alias)
            ip_data = get_ip_row(ip_address)
            if ip_data is None:
                self._respond_html(render_page("IP no encontrada", "error"))
            else:
                self._respond_html(render_edit_page(ip_data, msg, "success" if ok else "error"))
            return

        self.send_error(404)

    def _respond_html(self, html_body: str) -> None:
        data = html_body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def scheduler_loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        ping_all_registered_ips()
        stop_event.wait(PING_INTERVAL_SECONDS)


def run() -> None:
    init_db()
    stop_event = threading.Event()
    threading.Thread(target=scheduler_loop, args=(stop_event,), daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Servidor en http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.server_close()


if __name__ == "__main__":
    run()
