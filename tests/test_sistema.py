"""Pruebas del sistema en modo local. Ejecutar:  python -m pytest -q"""
import io
import os
import sys
import tempfile

os.environ["MODO_LOCAL"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import datos  # noqa: E402

_tmp = tempfile.mkdtemp()
datos.RUTA_JSON = os.path.join(_tmp, "datos.json")
datos.CARPETA_ARCHIVOS = os.path.join(_tmp, "archivos")

import pytest  # noqa: E402

import app as sistema  # noqa: E402
import reglas  # noqa: E402


@pytest.fixture(autouse=True)
def datos_limpios():
    if os.path.exists(datos.RUTA_JSON):
        os.remove(datos.RUTA_JSON)
    sistema.datos_de_ejemplo()


def cliente_de(correo, clave="Demo12345"):
    c = sistema.app.test_client()
    c.get("/login")
    with c.session_transaction() as s:
        t = s["csrf"]
    r = c.post("/login", data={"correo": correo, "clave": clave, "csrf": t})
    return c, r


def token(c):
    c.get("/perfil")
    with c.session_transaction() as s:
        return s["csrf"]


def un_caso():
    return sorted(datos.listar("vulnerabilidades"), key=lambda v: v["titulo"])[0]


def accion(c, vid, nombre, **campos):
    return c.post(f"/vulnerabilidades/{vid}/accion/{nombre}", data={"csrf": token(c), **campos})


def test_hay_usuarios_de_ejemplo_y_se_puede_entrar():
    for correo in ("admin", "responsable", "tecnico", "auditor", "gerencia"):
        c, r = cliente_de(f"{correo}@demo.local")
        assert r.status_code == 302 and r.headers["Location"].endswith("/panel"), correo
        assert c.get("/panel").status_code == 200


def test_clave_incorrecta_y_sin_sesion():
    c, r = cliente_de("admin@demo.local", "mala")
    assert r.status_code == 200 and b"incorrectos" in r.data
    assert sistema.app.test_client().get("/panel").status_code == 302


def test_reglas_de_prioridad():
    assert reglas.sugerir_prioridad("Baja", "Baja", "Baja", "Baja") == (3, "Baja")
    assert reglas.sugerir_prioridad("Crítica", "Crítica", "Crítica", "Alta") == (36, "Crítica")


MATRIZ = {"/usuarios": {"admin"}, "/auditoria": {"admin", "auditor"}, "/activos": {"admin", "responsable", "tecnico", "auditor"},
          "/activos/nuevo": {"admin"}, "/vulnerabilidades/nueva": {"admin", "responsable"},
          "/vulnerabilidades.csv": {"admin", "responsable", "auditor", "gerencia"},
          "/panel": {"admin", "responsable", "tecnico", "auditor", "gerencia"}}


@pytest.mark.parametrize("quien", ["admin", "responsable", "tecnico", "auditor", "gerencia"])
def test_permisos_por_rol(quien):
    c, _ = cliente_de(f"{quien}@demo.local")
    for ruta, permitidos in MATRIZ.items():
        assert c.get(ruta).status_code == (200 if quien in permitidos else 403), (quien, ruta)


def test_csrf_obligatorio():
    c, _ = cliente_de("admin@demo.local")
    assert c.post("/activos/nuevo", data={"nombre": "X", "tipo": "Laptop"}).status_code == 400


def test_usuario_inactivo_pierde_acceso():
    c, _ = cliente_de("tecnico@demo.local")
    tec = next(u for u in datos.listar("usuarios") if u["correo"] == "tecnico@demo.local")
    datos.actualizar("usuarios", tec["id"], {"estado": "Inactivo"})
    assert c.get("/panel").status_code == 302
    assert cliente_de("tecnico@demo.local")[1].status_code == 200


def test_ciclo_completo_hasta_cerrar():
    rs, _ = cliente_de("responsable@demo.local")
    tec_c, _ = cliente_de("tecnico@demo.local")
    tec = next(u for u in datos.listar("usuarios") if u["rol"] == "tecnico")
    vid = un_caso()["id"]
    estado = lambda: datos.obtener("vulnerabilidades", vid)["estado"]
    for a, campos in [("validar", {}), ("clasificar", {"impacto": "Alta", "probabilidad": "Media"}),
                      ("priorizar", {"prioridad": "Alta", "justificacion": "Es un servidor importante."}),
                      ("asignar", {"id_tecnico": tec["id"], "fecha_limite": "2099-01-01"})]:
        assert accion(rs, vid, a, **campos).status_code == 302
    assert estado() == "Asignada"
    accion(tec_c, vid, "iniciar")
    accion(tec_c, vid, "pedir_verificacion", actividad="Se instaló el parche.", evidencia="captura.png")
    assert estado() == "Pendiente de verificación"
    accion(rs, vid, "aprobar")
    accion(rs, vid, "cerrar")
    assert estado() == "Cerrada"
    assert len(datos.listar("seguimientos", id_vulnerabilidad=vid)) >= 8     # el historial se conserva
    assert any(a["accion"] == "Cambio de estado" for a in datos.listar("auditoria"))


def test_no_se_puede_saltar_estados_ni_cerrar_sin_verificacion():
    rs, _ = cliente_de("responsable@demo.local")
    vid = un_caso()["id"]
    for a in ("cerrar", "aprobar", "asignar", "priorizar"):
        accion(rs, vid, a)
    assert datos.obtener("vulnerabilidades", vid)["estado"] == "Registrada"
    datos.actualizar("vulnerabilidades", vid, {"estado": "Resuelta"})          # forzado, sin verificación
    accion(rs, vid, "cerrar")
    assert datos.obtener("vulnerabilidades", vid)["estado"] == "Resuelta"


def test_tecnico_y_gerencia_no_modifican():
    vid = un_caso()["id"]
    for quien in ("tecnico", "gerencia", "auditor"):
        c, _ = cliente_de(f"{quien}@demo.local")
        assert accion(c, vid, "validar").status_code in (403, 302)
        assert datos.obtener("vulnerabilidades", vid)["estado"] == "Registrada"
    c, _ = cliente_de("tecnico@demo.local")
    assert c.get(f"/vulnerabilidades/{vid}").status_code == 403          # caso no asignado a él
    assert any(a["accion"] == "Intento de acceso no autorizado" for a in datos.listar("auditoria"))


def test_validaciones_de_formularios():
    c, _ = cliente_de("responsable@demo.local")
    base = {"titulo": "[PRUEBA] Caso", "descripcion": "Descripción suficiente.", "tipo": "Otro", "fuente": "Revisión autorizada",
            "fecha_deteccion": "2026-01-01", "severidad": "Media", "id_activo": datos.listar("activos")[0]["id"], "csrf": token(c)}
    n = len(datos.listar("vulnerabilidades"))
    for cambio in ({"titulo": ""}, {"cve": "CVE-1"}, {"cvss": "11"}, {"id_activo": "ACT-NOEXISTE"},
                   {"fecha_deteccion": "2999-01-01"}, {"severidad": "Enorme"}):
        c.post("/vulnerabilidades/nueva", data={**base, **cambio})
    assert len(datos.listar("vulnerabilidades")) == n
    c.post("/vulnerabilidades/nueva", data={**base, "cve": "cve-2024-12345", "cvss": "7.5"})
    assert len(datos.listar("vulnerabilidades")) == n + 1


def test_ultimo_admin_no_se_puede_quitar():
    c, _ = cliente_de("admin@demo.local")
    adm = next(u for u in datos.listar("usuarios") if u["rol"] == "administrador")
    c.post(f"/usuarios/{adm['id']}/editar", data={"nombre": adm["nombre"], "rol": "tecnico", "estado": "Activo", "csrf": token(c)})
    assert datos.obtener("usuarios", adm["id"])["rol"] == "administrador"


def test_evidencias_validadas_y_privadas():
    rs, _ = cliente_de("responsable@demo.local")
    vid = un_caso()["id"]
    def subir(nombre, contenido):
        return rs.post(f"/vulnerabilidades/{vid}/evidencias", data={"csrf": token(rs), "archivo": (io.BytesIO(contenido), nombre)},
                       content_type="multipart/form-data")
    subir("virus.exe", b"MZ")
    subir("falso.pdf", b"no soy pdf")
    assert datos.listar("evidencias") == []
    subir("reporte.pdf", b"%PDF-1.4 contenido")
    e = datos.listar("evidencias")[0]
    assert rs.get(f"/evidencias/{e['id']}").data.startswith(b"%PDF")
    tec, _ = cliente_de("tecnico@demo.local")
    assert tec.get(f"/evidencias/{e['id']}").status_code == 403


def test_pantallas_y_accesibilidad():
    import re
    c, _ = cliente_de("admin@demo.local")
    vid = un_caso()["id"]
    for ruta in ("/panel", "/activos", "/vulnerabilidades", f"/vulnerabilidades/{vid}", f"/vulnerabilidades/{vid}/editar",
                 "/vulnerabilidades/nueva", "/activos/nuevo", "/usuarios", "/usuarios/nuevo", "/auditoria", "/perfil"):
        r = c.get(ruta)
        assert r.status_code == 200, ruta
        html = r.get_data(as_text=True)
        assert '<html lang="es">' in html
        for campo in re.findall(r'<(?:input|select|textarea)[^>]*\bid="([^"]+)"', html):
            assert f'for="{campo}"' in html, (ruta, campo)
    assert c.get("/vulnerabilidades/VUL-NOEXISTE").status_code == 404
    assert "default-src 'self'" in c.get("/panel").headers["Content-Security-Policy"]
