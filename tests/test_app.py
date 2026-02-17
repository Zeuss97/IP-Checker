import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app


def setup_module():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    app.DB_PATH = Path(tmp.name)
    app.init_db()


def test_invalid_ip_is_rejected():
    ok, msg = app.register_ip("not-an-ip", "x")
    assert ok is False
    assert "válida" in msg


def test_register_ip_and_ping():
    ok, _ = app.register_ip("127.0.0.1", "local")
    assert ok is True
    app.ping_all_registered_ips()

    with app.get_connection() as conn:
        row = conn.execute("SELECT last_status, last_ping_at FROM ip_registry WHERE ip_address = ?", ("127.0.0.1",)).fetchone()

    assert row is not None
    assert row["last_status"] in {"OK", "ERROR"}
    assert row["last_ping_at"] is not None


def test_segment_filter_supports_short_and_cidr_formats():
    app.register_ip("192.168.56.10", "seg56")
    app.register_ip("192.168.59.20", "seg59")

    short_filter = app.normalize_segment_filter("56/24")
    cidr_filter = app.normalize_segment_filter("192.168.59.0/24")

    short_rows = app.get_rows(segment_filter=short_filter)
    cidr_rows = app.get_rows(segment_filter=cidr_filter)

    assert short_filter == "THIRD_OCTET:56"
    assert cidr_filter == "192.168.59.0/24"
    assert any(r["ip_address"] == "192.168.56.10" for r in short_rows)
    assert all(r["segment"] == "192.168.59.0/24" for r in cidr_rows)


def test_host_details_can_be_updated():
    app.register_ip("192.168.60.15", "sin-detalles")
    ok, msg = app.update_host_details(
        ip_address="192.168.60.15",
        host_name="PABLO RIVEROS",
        host_type="NOTEBOOK",
        location="INF",
        notes="Equipo de pruebas",
        alias="PABLO",
    )

    assert ok is True
    assert "actualizado" in msg

    row = app.get_ip_row("192.168.60.15")
    assert row is not None
    assert row["host_name"] == "PABLO RIVEROS"
    assert row["host_type"] == "NOTEBOOK"
    assert row["location"] == "INF"
    assert row["notes"] == "Equipo de pruebas"
