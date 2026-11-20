"""Sistema de Gestión de Vulnerabilidades · Servicios Empresariales del Centro, S.A. de C.V.

Todo el programa está en tres archivos de Python:
  datos.py   guarda y lee datos (archivo local o Firebase)
  reglas.py  roles, permisos, estados y prioridad
  app.py     este archivo: pantallas, validaciones y lógica
Ejecutar:  python app.py   ->  http://127.0.0.1:5000
"""
import csv
import hmac
import io
import ipaddress
import os
import re
import secrets
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import datos
import reglas

EMPRESA = "Servicios Empresariales del Centro, S.A. de C.V."
PRODUCCION = os.getenv("ENTORNO") == "produccion"
DIAS_AVISO = 3                    # "próximo a vencer" = faltan 3 días o menos
MAX_MB = 5
EXTENSIONES = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".log", ".docx", ".xlsx"}

SECRET_KEY = os.getenv("SECRET_KEY", "")
if PRODUCCION and not SECRET_KEY:
    raise RuntimeError("Falta la variable SECRET_KEY.")
if PRODUCCION and datos.MODO_LOCAL:
    raise RuntimeError("En producción usa MODO_LOCAL=0 (Firebase).")

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY or "solo-para-desarrollo", SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=PRODUCCION,
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=(MAX_MB + 1) * 1024 * 1024)
app.jinja_env.policies["json.dumps_kwargs"] = {"sort_keys": False}


class Error(Exception):
    """Dato o regla incumplida: el mensaje se muestra al usuario."""


class SinPermiso(Exception):
    pass


# ============================================================ utilidades
def ahora():
    return datetime.now().isoformat(timespec="microseconds")


def hoy():
    return date.today().isoformat()


def texto(f, campo, nombre, obligatorio=True, minimo=1, maximo=200):
    v = str(f.get(campo) or "").strip()
    if not v:
        if obligatorio:
            raise Error(f"{nombre} es obligatorio.")
        return ""
    if len(v) < minimo:
        raise Error(f"{nombre} necesita al menos {minimo} caracteres.")
    if len(v) > maximo:
        raise Error(f"{nombre} no puede pasar de {maximo} caracteres.")
    return v


def opcion(f, campo, nombre, validas, defecto=""):
    v = str(f.get(campo) or "").strip() or defecto
    if v not in validas:
        raise Error(f"Elige un valor válido en «{nombre}».")
    return v


def fecha(valor, nombre):
    try:
        return date.fromisoformat(str(valor or "").strip()).isoformat()
    except ValueError:
        raise Error(f"{nombre} no es una fecha válida.")


def registrar(usuario, accion, modulo, id_registro="", resultado="Correcto", detalle=""):
    """Bitácora de auditoría. Nunca se guardan contraseñas ni tokens."""
    datos.crear("auditoria", {"id_usuario": usuario["id"] if usuario else None,
                              "usuario": usuario["nombre"] if usuario else "Sistema", "accion": accion,
                              "modulo": modulo, "id_registro": id_registro, "fecha_hora": ahora(),
                              "resultado": resultado, "detalle": str(detalle)[:300]}, datos.nuevo_id("AUD"))


def mas_reciente_primero(filas, campo):
    return sorted(filas, key=lambda x: x.get(campo) or "", reverse=True)


# ======================================================= seguridad básica
def token_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def antes():
    g.usuario = None
    u = datos.obtener("usuarios", session.get("uid"))
    if u and u.get("estado") == "Activo":          # se relee en cada petición: si lo desactivan, pierde acceso
        g.usuario = u
    elif session.get("uid"):
        session.clear()
    if request.method == "POST":
        enviado = request.form.get("csrf") or request.headers.get("X-CSRF-Token") or ""
        if not hmac.compare_digest(enviado, session.get("csrf", "-")):
            abort(400, "El formulario caducó. Recarga la página e inténtalo de nuevo.")


@app.after_request
def cabeceras(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://www.gstatic.com; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; "
        "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com")
    if not request.path.startswith("/static/"):
        r.headers["Cache-Control"] = "private, no-store"
    return r


@app.context_processor
def comunes():
    return {"csrf": token_csrf(), "usuario": g.get("usuario"), "ROLES": reglas.ROLES, "EMPRESA": EMPRESA,
            "MODO_LOCAL": datos.MODO_LOCAL,
            "puede": lambda p: bool(g.get("usuario")) and reglas.puede(g.usuario["rol"], p)}


@app.template_filter("fecha")
def _fecha(v):
    try:
        return datetime.fromisoformat(v).strftime("%d/%m/%Y")
    except (TypeError, ValueError):
        return v or "—"


@app.template_filter("fecha_hora")
def _fecha_hora(v):
    try:
        return datetime.fromisoformat(v).strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError):
        return v or "—"


def requiere(permiso=None):
    def deco(f):
        @wraps(f)
        def envoltura(*a, **k):
            if not g.usuario:
                return redirect(url_for("login"))
            if permiso and not reglas.puede(g.usuario["rol"], permiso):
                raise SinPermiso(permiso)
            return f(*a, **k)
        return envoltura
    return deco


@app.errorhandler(Error)
def error_de_regla(e):
    flash(str(e), "error")
    if request.method == "POST" and request.endpoint in ("activo_nuevo", "activo_editar", "vuln_nueva", "vuln_editar",
                                                          "usuario_nuevo", "usuario_editar"):
        # Se guardan los datos escritos para no obligar a capturarlos de nuevo (sin contraseñas).
        vals = {k: v[:600] for k, v in request.form.items() if k not in ("csrf", "clave")}
        if sum(len(v) for v in vals.values()) < 2500:
            session["_form"] = {"ep": request.endpoint, "vals": vals}
    return redirect(request.referrer or url_for("panel"))


def recuperar(base):
    """Datos del formulario con error (si los hay) sobre los valores originales."""
    guardado = session.pop("_form", None)
    return {**base, **guardado["vals"]} if guardado and guardado["ep"] == request.endpoint else base


def _pagina(codigo, titulo, mensaje):
    return render_template("error.html", codigo=codigo, titulo=titulo, mensaje=mensaje), codigo


@app.errorhandler(SinPermiso)
def sin_permiso(e):
    registrar(g.get("usuario"), "Intento de acceso no autorizado", "Seguridad", "", "Denegado",
              f"{request.method} {request.path}")
    return _pagina(403, "Acceso denegado", "Tu rol no puede hacer esto.")


@app.errorhandler(400)
def e400(e):
    return _pagina(400, "Solicitud no válida", getattr(e, "description", ""))


@app.errorhandler(404)
def e404(e):
    return _pagina(404, "No encontrado", "La página o el registro no existe.")


@app.errorhandler(413)
def e413(e):
    return _pagina(413, "Archivo demasiado grande", f"El máximo es {MAX_MB} MB.")


@app.errorhandler(500)
def e500(e):
    return _pagina(500, "Ocurrió un error", "No se pudo completar la operación. Inténtalo de nuevo.")


# ============================================================ sesión
def iniciar_sesion(u):
    session.clear()
    session.permanent = True
    session["uid"] = u["id"]
    datos.actualizar("usuarios", u["id"], {"ultimo_acceso": ahora()})
    registrar(u, "Inicio de sesión", "Acceso", u["id"])


@app.get("/")
def inicio():
    return redirect(url_for("panel" if session.get("uid") else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST" and datos.MODO_LOCAL:
        correo = (request.form.get("correo") or "").strip().lower()
        u = next((x for x in datos.listar("usuarios") if x["correo"] == correo), None)
        if u and u["estado"] == "Activo" and check_password_hash(u.get("clave_hash", ""), request.form.get("clave", "")):
            iniciar_sesion(u)
            return redirect(url_for("panel"))
        registrar(None, "Inicio de sesión fallido", "Seguridad", "", "Denegado", correo[:100])
        flash("Correo o contraseña incorrectos.", "error")
    return render_template("login.html")


@app.post("/sesion")
def sesion_firebase():
    """Firebase: el navegador inicia sesión en Firebase y nos manda su token; aquí se verifica."""
    if datos.MODO_LOCAL:
        abort(404)
    from firebase_admin import auth
    try:
        dec = auth.verify_id_token((request.get_json(silent=True) or {}).get("idToken", ""))
    except Exception:
        return jsonify(error="No se pudo verificar tu sesión."), 401
    u = datos.obtener("usuarios", dec["uid"])
    if not u or u.get("estado") != "Activo":
        registrar(None, "Inicio de sesión fallido", "Seguridad", dec["uid"], "Denegado", "Sin perfil o inactivo")
        return jsonify(error="Tu cuenta no tiene acceso al sistema. Pide al administrador que la registre."), 403
    iniciar_sesion(u)
    return jsonify(ok=True)


@app.post("/salir")
def salir():
    session.clear()
    return redirect(url_for("login"))


# ===================================================== datos de consulta
def vulns_visibles():
    todas = datos.listar("vulnerabilidades")
    if reglas.puede(g.usuario["rol"], "ver_todo"):
        base = todas
    else:
        base = [v for v in todas if v.get("id_tecnico") == g.usuario["id"]]
    activos = {a["id"]: a for a in datos.listar("activos")}
    for v in base:
        a = activos.get(v.get("id_activo"))
        v["activo_nombre"] = a["nombre"] if a else "Sin activo"
        v["tipo_activo"] = a["tipo"] if a else "Sin activo"
        v["alerta"] = alerta_fecha(v)
    peso = {n: i for i, n in enumerate(reglas.NIVELES_ORDEN)}
    return sorted(base, key=lambda v: (peso.get(v.get("prioridad") or v["severidad"], 9), v["fecha_registro"]))


def alerta_fecha(v):
    if v["estado"] not in reglas.ABIERTOS or not v.get("fecha_limite"):
        return None
    dias = (date.fromisoformat(v["fecha_limite"]) - date.today()).days
    return "vencida" if dias < 0 else "próxima a vencer" if dias <= DIAS_AVISO else None


def contar(vulns, campo, orden=None):
    c = {k: 0 for k in (orden or [])}
    for v in vulns:
        k = v.get(campo) or "Sin asignar"
        c[k] = c.get(k, 0) + 1
    return c


@app.get("/panel")
@requiere()
def panel():
    vulns = vulns_visibles()
    abiertas = [v for v in vulns if v["estado"] in reglas.ABIERTOS]
    ind = {
        "Vulnerabilidades": len(vulns),
        "Críticas abiertas": sum(v["severidad"] == "Crítica" for v in abiertas),
        "Prioridad alta": sum(v.get("prioridad") == "Alta" for v in abiertas),
        "Pendientes": sum(v["estado"] in reglas.PENDIENTES for v in vulns),
        "En atención": sum(v["estado"] in reglas.EN_ATENCION for v in vulns),
        "Resueltas": sum(v["estado"] == "Resuelta" for v in vulns),
        "Cerradas": sum(v["estado"] == "Cerrada" for v in vulns),
        "Vencidas": sum(v["alerta"] == "vencida" for v in vulns),
        "Próximas a vencer": sum(v["alerta"] == "próxima a vencer" for v in vulns),
    }
    if reglas.puede(g.usuario["rol"], "activos_ver"):
        ind["Activos"] = len(datos.listar("activos"))
    # Alertas calculadas con los datos actuales (no se envían correos)
    alertas = [("Caso vencido", v) for v in abiertas if v["alerta"] == "vencida"]
    alertas += [("Próximo a vencer", v) for v in abiertas if v["alerta"] == "próxima a vencer"]
    alertas += [("Crítica pendiente", v) for v in abiertas
                if v["severidad"] == "Crítica" and v["estado"] in reglas.PENDIENTES]
    graficas = {"severidad": contar(vulns, "severidad", reglas.NIVELES_ORDEN),
                "estado": contar(vulns, "estado", reglas.ESTADOS),
                "tipo": contar(vulns, "tipo_activo"), "responsable": contar(abiertas, "tecnico_nombre")}
    return render_template("panel.html", ind=ind, alertas=alertas, urgentes=abiertas[:6], graficas=graficas,
                           hay_datos=bool(vulns))


# ============================================================ activos
def leer_activo(f):
    ip = texto(f, "ip", "La IP", False, maximo=45)
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise Error("La dirección IP no es válida.")
    return {"nombre": texto(f, "nombre", "El nombre", minimo=2, maximo=120),
            "tipo": opcion(f, "tipo", "Tipo de activo", reglas.TIPOS_ACTIVO),
            "marca": texto(f, "marca", "La marca", False, maximo=60), "modelo": texto(f, "modelo", "El modelo", False, maximo=60),
            "serie": texto(f, "serie", "La serie", False, maximo=60),
            "sistema": texto(f, "sistema", "El sistema operativo", False, maximo=60), "ip": ip,
            "ubicacion": texto(f, "ubicacion", "La ubicación", False, maximo=100),
            "responsable": texto(f, "responsable", "El responsable", False, maximo=100),
            "criticidad": opcion(f, "criticidad", "Criticidad", reglas.NIVELES, "Media")}


@app.get("/activos")
@requiere("activos_ver")
def activos():
    abiertas = {}
    for v in datos.listar("vulnerabilidades"):
        if v["estado"] in reglas.ABIERTOS and v.get("id_activo"):
            abiertas[v["id_activo"]] = abiertas.get(v["id_activo"], 0) + 1
    lista = sorted(datos.listar("activos"), key=lambda a: a["nombre"].lower())
    return render_template("activos.html", activos=lista, abiertas=abiertas)


@app.route("/activos/nuevo", methods=["GET", "POST"])
@requiere("activos")
def activo_nuevo():
    if request.method == "POST":
        a = leer_activo(request.form)
        a.update(estado="Activo", fecha_registro=ahora())
        aid = datos.crear("activos", a, datos.nuevo_id("ACT"))
        registrar(g.usuario, "Registro de activo", "Activos", aid, detalle=a["nombre"])
        flash("Activo registrado.", "ok")
        return redirect(url_for("activos"))
    return render_template("activo_form.html", a=recuperar({"criticidad": "Media"}), editar=False, tipos=reglas.TIPOS_ACTIVO,
                           niveles=list(reglas.NIVELES))


@app.route("/activos/<aid>/editar", methods=["GET", "POST"])
@requiere("activos")
def activo_editar(aid):
    actual = datos.obtener("activos", aid) or abort(404)
    if request.method == "POST":
        a = leer_activo(request.form)
        a["estado"] = opcion(request.form, "estado", "Estado", ["Activo", "Inactivo"], actual["estado"])
        if a["estado"] == "Inactivo" and any(v["estado"] in reglas.ABIERTOS for v in
                                              datos.listar("vulnerabilidades", id_activo=aid)):
            raise Error("No se puede desactivar: tiene vulnerabilidades abiertas.")
        datos.actualizar("activos", aid, a)
        registrar(g.usuario, "Modificación de activo", "Activos", aid, detalle=a["nombre"])
        flash("Activo actualizado.", "ok")
        return redirect(url_for("activos"))
    return render_template("activo_form.html", a=recuperar(actual), editar=True, aid=aid, tipos=reglas.TIPOS_ACTIVO,
                           niveles=list(reglas.NIVELES))


# ====================================================== vulnerabilidades
def leer_vuln(f):
    v = {"titulo": texto(f, "titulo", "El título", minimo=5, maximo=150),
         "descripcion": texto(f, "descripcion", "La descripción", minimo=10, maximo=2000),
         "tipo": opcion(f, "tipo", "Tipo de vulnerabilidad", reglas.TIPOS_VULN),
         "fuente": opcion(f, "fuente", "Fuente", reglas.FUENTES),
         "fecha_deteccion": fecha(f.get("fecha_deteccion"), "La fecha de detección"),
         "severidad": opcion(f, "severidad", "Severidad", reglas.NIVELES),
         "cve": texto(f, "cve", "El CVE", False, maximo=30).upper(),
         "id_activo": str(f.get("id_activo") or "").strip(),
         "justificacion": texto(f, "justificacion", "La justificación", False, maximo=500)}
    if v["fecha_deteccion"] > hoy():
        raise Error("La fecha de detección no puede ser futura.")
    if v["cve"] and not re.match(r"^CVE-\d{4}-\d{4,}$", v["cve"]):
        raise Error("El CVE debe verse así: CVE-2024-12345.")
    cvss = str(f.get("cvss") or "").strip()
    try:
        v["cvss"] = float(cvss) if cvss else None
        if v["cvss"] is not None and not 0 <= v["cvss"] <= 10:
            raise ValueError
    except ValueError:
        raise Error("El CVSS debe ser un número de 0 a 10.")
    if v["id_activo"]:
        a = datos.obtener("activos", v["id_activo"])
        if not a or a["estado"] != "Activo":
            raise Error("El activo elegido no existe o está desactivado.")
    elif len(v["justificacion"]) < 10:
        raise Error("Elige un activo, o justifica el registro temporal sin activo (mínimo 10 caracteres).")
    return v


def seguimiento(vid, usuario, actividad, observaciones="", estado=""):
    """Historial: solo se agregan registros, nunca se editan ni se borran."""
    datos.crear("seguimientos", {"id_vulnerabilidad": vid, "usuario": usuario["nombre"], "actividad": actividad,
                                 "observaciones": observaciones, "estado": estado, "fecha": ahora()},
                datos.nuevo_id("SEG"))


def caso(vid):
    v = datos.obtener("vulnerabilidades", vid) or abort(404)
    if not reglas.puede_ver(v, g.usuario):
        raise SinPermiso(f"ver {vid}")
    return v


@app.get("/vulnerabilidades")
@requiere()
def vulns():
    f = {k: request.args.get(k, "").strip() for k in ("texto", "estado", "severidad", "prioridad")}
    lista = vulns_filtradas(f)
    return render_template("vulns.html", vulns=lista, f=f, estados=reglas.ESTADOS, niveles=reglas.NIVELES_ORDEN)


def vulns_filtradas(f):
    q = f["texto"].lower()
    return [v for v in vulns_visibles()
            if (not f["estado"] or v["estado"] == f["estado"]) and (not f["severidad"] or v["severidad"] == f["severidad"])
            and (not f["prioridad"] or v.get("prioridad") == f["prioridad"])
            and (not q or q in f"{v['titulo']} {v.get('cve', '')} {v['id']}".lower())]


@app.get("/vulnerabilidades.csv")
@requiere("reportes")
def vulns_csv():
    f = {k: request.args.get(k, "").strip() for k in ("texto", "estado", "severidad", "prioridad")}
    salida = io.StringIO()
    w = csv.writer(salida)
    w.writerow(["ID", "Título", "Activo", "Severidad", "Prioridad", "Estado", "Responsable", "Fecha límite"])
    seguro = lambda x: "'" + str(x) if str(x)[:1] in "=+-@" else x     # evita fórmulas en Excel
    for v in vulns_filtradas(f):
        w.writerow([seguro(x) for x in (v["id"], v["titulo"], v["activo_nombre"], v["severidad"],
                                        v.get("prioridad") or "", v["estado"], v.get("tecnico_nombre") or "",
                                        v.get("fecha_limite") or "")])
    registrar(g.usuario, "Exportación CSV", "Reportes")
    return Response("﻿" + salida.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=vulnerabilidades.csv"})


def activos_activos():
    return sorted([a for a in datos.listar("activos") if a["estado"] == "Activo"], key=lambda a: a["nombre"].lower())


@app.route("/vulnerabilidades/nueva", methods=["GET", "POST"])
@requiere("registrar")
def vuln_nueva():
    if request.method == "POST":
        v = leer_vuln(request.form)
        v.update(estado="Registrada", registrado_por=g.usuario["nombre"], fecha_registro=ahora(), veces_reabierta=0)
        vid = datos.crear("vulnerabilidades", v, datos.nuevo_id("VUL"))
        seguimiento(vid, g.usuario, "Registro de la vulnerabilidad", v["fuente"], "Registrada")
        registrar(g.usuario, "Creación de vulnerabilidad", "Vulnerabilidades", vid, detalle=v["titulo"])
        flash("Vulnerabilidad registrada.", "ok")
        return redirect(url_for("vuln_detalle", vid=vid))
    return render_template("vuln_form.html", v=recuperar({"severidad": "Media"}), editar=False, activos=activos_activos(),
                           tipos=reglas.TIPOS_VULN, fuentes=reglas.FUENTES, niveles=list(reglas.NIVELES))


@app.route("/vulnerabilidades/<vid>/editar", methods=["GET", "POST"])
@requiere("registrar")
def vuln_editar(vid):
    v = caso(vid)
    if v["estado"] == "Cerrada":
        raise Error("El caso está cerrado; reábrelo para modificarlo.")
    if request.method == "POST":
        nuevo = leer_vuln(request.form)
        datos.actualizar("vulnerabilidades", vid, nuevo)
        seguimiento(vid, g.usuario, "Modificación de los datos del registro", "", v["estado"])
        registrar(g.usuario, "Modificación de vulnerabilidad", "Vulnerabilidades", vid, detalle=nuevo["titulo"])
        if nuevo["severidad"] != v["severidad"]:
            registrar(g.usuario, "Cambio de severidad", "Vulnerabilidades", vid, detalle=f"{v['severidad']} → {nuevo['severidad']}")
        flash("Registro actualizado.", "ok")
        return redirect(url_for("vuln_detalle", vid=vid))
    return render_template("vuln_form.html", v=recuperar(v), vid=vid, editar=True, activos=activos_activos(),
                           tipos=reglas.TIPOS_VULN, fuentes=reglas.FUENTES, niveles=list(reglas.NIVELES))


@app.get("/vulnerabilidades/<vid>")
@requiere()
def vuln_detalle(vid):
    v = caso(vid)
    v["alerta"] = alerta_fecha(v)
    evals = mas_reciente_primero(datos.listar("evaluaciones", id_vulnerabilidad=vid), "fecha")
    return render_template(
        "vuln_detalle.html", v=v, activo=datos.obtener("activos", v.get("id_activo")),
        historial=mas_reciente_primero(datos.listar("seguimientos", id_vulnerabilidad=vid), "fecha"),
        evaluacion=evals[0] if evals else None,
        asignaciones=mas_reciente_primero(datos.listar("asignaciones", id_vulnerabilidad=vid), "fecha"),
        verificaciones=mas_reciente_primero(datos.listar("verificaciones", id_vulnerabilidad=vid), "fecha"),
        evidencias=mas_reciente_primero([e for e in datos.listar("evidencias", id_vulnerabilidad=vid)], "fecha"),
        acciones=reglas.acciones_disponibles(v, g.usuario), ACCIONES=reglas.ACCIONES,
        tecnicos=sorted(datos.listar("usuarios", rol="tecnico", estado="Activo"), key=lambda u: u["nombre"]),
        niveles=list(reglas.NIVELES), probabilidades=list(reglas.PROBABILIDADES), hoy=hoy(),
        puede_adjuntar=v["estado"] != "Cerrada" and (reglas.puede(g.usuario["rol"], "gestionar")
                                                      or (g.usuario["rol"] == "tecnico" and v.get("id_tecnico") == g.usuario["id"])))


@app.post("/vulnerabilidades/<vid>/accion/<accion>")
@requiere()
def vuln_accion(vid, accion):
    etiqueta = aplicar_accion(caso(vid), g.usuario, accion, request.form)
    flash(f"Listo: {etiqueta}.", "ok")
    return redirect(url_for("vuln_detalle", vid=vid))


def aplicar_accion(v, u, accion, f):
    """Única puerta para cambiar el estado: valida permiso, estado de origen y datos.
    La usan la pantalla (vuln_accion) y el script de datos de ejemplo."""
    vid = v["id"]
    if accion not in reglas.ACCIONES:
        raise Error("Acción desconocida.")
    origen, destino, permiso, etiqueta = reglas.ACCIONES[accion]
    if accion not in reglas.acciones_disponibles(v, u):
        if not reglas.puede(u["rol"], permiso) or (permiso == "atender" and v.get("id_tecnico") != u["id"]):
            raise SinPermiso(f"{accion} en {vid}")
        raise Error(f"«{etiqueta}» no está disponible cuando el caso está «{v['estado']}».")
    cambios = {}
    obs = texto(f, "observaciones", "Las observaciones", False, maximo=1000)
    actividad = etiqueta

    if accion == "validar":
        if v.get("id_activo") and not datos.obtener("activos", v["id_activo"]):
            raise Error("El activo asociado ya no existe.")
        for o in datos.listar("vulnerabilidades", id_activo=v.get("id_activo")):
            if v.get("id_activo") and o["id"] != vid and o["estado"] != "Cerrada" and o["titulo"].lower() == v["titulo"].lower():
                raise Error(f"Posible duplicado: ya existe el caso {o['id']} con el mismo título en este activo.")
        actividad = "Información validada"

    elif accion == "clasificar":
        activo = datos.obtener("activos", v.get("id_activo"))
        if not activo:
            raise Error("Asocia un activo a la vulnerabilidad antes de clasificarla.")
        impacto = opcion(f, "impacto", "Impacto empresarial", reglas.NIVELES)
        prob = opcion(f, "probabilidad", "Probabilidad", reglas.PROBABILIDADES)
        puntaje, sugerida = reglas.sugerir_prioridad(v["severidad"], activo["criticidad"], impacto, prob)
        datos.crear("evaluaciones", {"id_vulnerabilidad": vid, "cvss": v.get("cvss"), "criticidad_activo": activo["criticidad"],
                                     "impacto_empresarial": impacto, "probabilidad": prob, "puntaje": puntaje,
                                     "prioridad_sugerida": sugerida, "prioridad": None, "justificacion": "",
                                     "evaluado_por": u["nombre"], "fecha": ahora()}, datos.nuevo_id("EVA"))
        actividad = f"Clasificado: impacto {impacto}, probabilidad {prob} (sugerida: {sugerida})"

    elif accion == "priorizar":
        ev = mas_reciente_primero(datos.listar("evaluaciones", id_vulnerabilidad=vid), "fecha")[0]
        prioridad = opcion(f, "prioridad", "Prioridad", reglas.NIVELES)
        just = texto(f, "justificacion", "La justificación de la prioridad", minimo=10, maximo=500)
        datos.actualizar("evaluaciones", ev["id"], {"prioridad": prioridad, "justificacion": just})
        cambios["prioridad"] = prioridad
        actividad, obs = f"Prioridad establecida: {prioridad}", just

    elif accion == "asignar":
        t = datos.obtener("usuarios", f.get("id_tecnico"))
        if not t or t["estado"] != "Activo" or t["rol"] != "tecnico":
            raise Error("Elige un técnico de TI activo.")
        limite = fecha(f.get("fecha_limite"), "La fecha límite")
        if limite < hoy():
            raise Error("La fecha límite no puede estar en el pasado.")
        for a in datos.listar("asignaciones", id_vulnerabilidad=vid, estado="Vigente"):
            datos.actualizar("asignaciones", a["id"], {"estado": "Reasignada"})
        datos.crear("asignaciones", {"id_vulnerabilidad": vid, "id_tecnico": t["id"], "tecnico": t["nombre"],
                                     "fecha": ahora(), "fecha_limite": limite, "estado": "Vigente",
                                     "observaciones": obs, "asignado_por": u["nombre"]}, datos.nuevo_id("ASG"))
        cambios.update(id_tecnico=t["id"], tecnico_nombre=t["nombre"], fecha_limite=limite)
        if v["estado"] == "Priorizada":
            cambios["estado"] = "Asignada"
        actividad = f"Asignado a {t['nombre']} · fecha límite {limite}"

    elif accion == "avance":
        actividad = texto(f, "actividad", "La actividad realizada", minimo=5, maximo=1000)

    elif accion == "pedir_verificacion":
        actividad = texto(f, "actividad", "La corrección realizada", minimo=5, maximo=1000)
        obs = texto(f, "evidencia", "La evidencia de la solución", maximo=1000)

    elif accion in ("aprobar", "rechazar"):
        if accion == "rechazar" and not obs:
            raise Error("Explica por qué la solución no es correcta.")
        datos.crear("verificaciones", {"id_vulnerabilidad": vid, "verificado_por": u["nombre"], "fecha": ahora(),
                                       "resultado": "Aprobada" if accion == "aprobar" else "Rechazada",
                                       "observaciones": obs, "fecha_cierre": None}, datos.nuevo_id("VER"))
        if accion == "aprobar":
            cambios["fecha_resolucion"] = hoy()
            for a in datos.listar("asignaciones", id_vulnerabilidad=vid, estado="Vigente"):
                datos.actualizar("asignaciones", a["id"], {"estado": "Completada"})
        else:
            cambios["veces_reabierta"] = v.get("veces_reabierta", 0) + 1

    elif accion == "cerrar":
        ver = sorted(datos.listar("verificaciones", id_vulnerabilidad=vid), key=lambda x: x["fecha"])
        if not ver or ver[-1]["resultado"] != "Aprobada":
            raise Error("No se puede cerrar: falta una verificación aprobada.")
        datos.actualizar("verificaciones", ver[-1]["id"], {"fecha_cierre": hoy()})
        cambios["fecha_cierre"] = hoy()

    elif accion == "reabrir":
        if not obs:
            raise Error("Escribe el motivo de la reapertura.")
        cambios.update(fecha_resolucion=None, fecha_cierre=None, veces_reabierta=v.get("veces_reabierta", 0) + 1)

    if destino:
        cambios["estado"] = destino
    if cambios:
        datos.actualizar("vulnerabilidades", vid, cambios)
    nuevo_estado = cambios.get("estado", v["estado"])
    seguimiento(vid, u, actividad, obs, nuevo_estado)
    detalle = f"{v['estado']} → {nuevo_estado}" if nuevo_estado != v["estado"] else actividad[:200]
    registrar(u, "Cambio de estado" if nuevo_estado != v["estado"] else etiqueta, "Vulnerabilidades", vid, detalle=detalle)
    return etiqueta


# ============================================================ evidencias
FIRMAS = {".pdf": b"%PDF", ".png": b"\x89PNG", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
          ".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04"}


@app.post("/vulnerabilidades/<vid>/evidencias")
@requiere()
def evidencia_subir(vid):
    v = caso(vid)
    es_suyo = g.usuario["rol"] == "tecnico" and v.get("id_tecnico") == g.usuario["id"]
    if not (reglas.puede(g.usuario["rol"], "gestionar") or es_suyo):
        raise SinPermiso("adjuntar evidencia")
    if v["estado"] == "Cerrada":
        raise Error("El caso está cerrado.")
    archivo = request.files.get("archivo")
    if not archivo or not archivo.filename:
        raise Error("Selecciona un archivo.")
    nombre = secure_filename(archivo.filename) or "archivo"
    ext = os.path.splitext(nombre)[1].lower()
    if ext not in EXTENSIONES:
        raise Error(f"Tipo de archivo no permitido. Se aceptan: {', '.join(sorted(EXTENSIONES))}.")
    contenido = archivo.read(MAX_MB * 1024 * 1024 + 1)
    if not contenido:
        raise Error("El archivo está vacío.")
    if len(contenido) > MAX_MB * 1024 * 1024:
        raise Error(f"El archivo supera {MAX_MB} MB.")
    if ext in FIRMAS and not contenido.startswith(FIRMAS[ext]):
        raise Error("El contenido del archivo no corresponde a su extensión.")
    if not datos.MODO_LOCAL and not datos.STORAGE_BUCKET:
        raise Error("Falta configurar STORAGE_BUCKET para guardar evidencias.")
    ruta = f"evidencias/{vid}/{secrets.token_hex(4)}_{nombre}"
    datos.guardar_archivo(ruta, contenido, archivo.mimetype or "application/octet-stream")
    eid = datos.crear("evidencias", {"id_vulnerabilidad": vid, "nombre": nombre, "ruta": ruta, "tamano": len(contenido),
                                     "mime": archivo.mimetype or "application/octet-stream",
                                     "subido_por": g.usuario["nombre"], "fecha": ahora()}, datos.nuevo_id("EVD"))
    seguimiento(vid, g.usuario, f"Evidencia cargada: {nombre}", "", v["estado"])
    registrar(g.usuario, "Carga de evidencia", "Evidencias", eid, detalle=nombre)
    flash("Evidencia cargada.", "ok")
    return redirect(url_for("vuln_detalle", vid=vid))


@app.get("/evidencias/<eid>")
@requiere()
def evidencia_ver(eid):
    e = datos.obtener("evidencias", eid) or abort(404)
    caso(e["id_vulnerabilidad"])                        # solo quien puede ver el caso
    registrar(g.usuario, "Consulta de evidencia", "Evidencias", eid)
    return Response(datos.leer_archivo(e["ruta"]), mimetype=e["mime"],
                    headers={"Content-Disposition": f'attachment; filename="{e["nombre"]}"'})


# ============================================================ usuarios
def crear_usuario(f, actor=None):
    """Crea la cuenta (en Firebase Authentication o local) y su perfil. actor=None: primer administrador."""
    nombre = texto(f, "nombre", "El nombre", minimo=3, maximo=100)
    correo = texto(f, "correo", "El correo", maximo=120).lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", correo):
        raise Error("El correo no es válido.")
    rol = opcion(f, "rol", "Rol", reglas.ROLES)
    clave = str(f.get("clave") or "")
    if len(clave) < 8:
        raise Error("La contraseña debe tener al menos 8 caracteres.")
    if any(u["correo"] == correo for u in datos.listar("usuarios")):
        raise Error("Ya existe un usuario con ese correo.")
    perfil = {"nombre": nombre, "correo": correo, "departamento": texto(f, "departamento", "El departamento", False, maximo=100),
              "rol": rol, "estado": "Activo", "fecha_registro": ahora(), "ultimo_acceso": None}
    if datos.MODO_LOCAL:
        perfil["clave_hash"] = generate_password_hash(clave)      # solo en modo local
        uid = datos.nuevo_id("USR")
    else:
        from firebase_admin import auth                              # la contraseña vive solo en Firebase
        try:
            uid = auth.create_user(email=correo, password=clave, display_name=nombre).uid
        except Exception as e:
            raise Error(f"Firebase no pudo crear la cuenta: {e}")
    datos.crear("usuarios", perfil, uid)
    registrar(actor, "Creación de usuario", "Usuarios", uid, detalle=f"{correo} · {reglas.ROLES[rol]}")
    return uid


@app.get("/usuarios")
@requiere("usuarios")
def usuarios():
    return render_template("usuarios.html", lista=sorted(datos.listar("usuarios"), key=lambda u: u["nombre"].lower()),
                           permisos=reglas.PERMISOS)


@app.route("/usuarios/nuevo", methods=["GET", "POST"])
@requiere("usuarios")
def usuario_nuevo():
    if request.method == "POST":
        crear_usuario(request.form, g.usuario)
        flash("Usuario creado.", "ok")
        return redirect(url_for("usuarios"))
    return render_template("usuario_form.html", u=recuperar({"rol": "tecnico"}), editar=False)


@app.route("/usuarios/<uid>/editar", methods=["GET", "POST"])
@requiere("usuarios")
def usuario_editar(uid):
    u = datos.obtener("usuarios", uid) or abort(404)
    if request.method == "POST":
        f = request.form
        cambios = {"nombre": texto(f, "nombre", "El nombre", minimo=3, maximo=100),
                   "departamento": texto(f, "departamento", "El departamento", False, maximo=100),
                   "rol": opcion(f, "rol", "Rol", reglas.ROLES), "estado": opcion(f, "estado", "Estado", ["Activo", "Inactivo"])}
        clave = str(f.get("clave") or "")
        if clave and len(clave) < 8:
            raise Error("La nueva contraseña debe tener al menos 8 caracteres.")
        deja_de_ser_admin = u["rol"] == "administrador" and (cambios["rol"] != "administrador" or cambios["estado"] != "Activo")
        if deja_de_ser_admin and (uid == g.usuario["id"] or not [x for x in datos.listar("usuarios", rol="administrador", estado="Activo") if x["id"] != uid]):
            raise Error("Debe quedar al menos un administrador activo; no puedes quitarte ese rol a ti mismo.")
        if datos.MODO_LOCAL:
            if clave:
                cambios["clave_hash"] = generate_password_hash(clave)
        else:
            from firebase_admin import auth
            try:
                extra = {"password": clave} if clave else {}
                auth.update_user(uid, display_name=cambios["nombre"], disabled=cambios["estado"] == "Inactivo", **extra)
            except Exception as e:
                raise Error(f"Firebase no pudo actualizar la cuenta: {e}")
        datos.actualizar("usuarios", uid, cambios)
        if cambios["rol"] != u["rol"]:
            registrar(g.usuario, "Modificación de rol", "Usuarios", uid, detalle=f"{u['correo']}: {u['rol']} → {cambios['rol']}")
        if cambios["estado"] != u["estado"]:
            registrar(g.usuario, "Cambio de estado de usuario", "Usuarios", uid, detalle=f"{u['correo']}: {cambios['estado']}")
        flash("Usuario actualizado.", "ok")
        return redirect(url_for("usuarios"))
    return render_template("usuario_form.html", u=recuperar(u), editar=True, uid=uid)


@app.get("/auditoria")
@requiere("auditoria")
def auditoria():
    q = request.args.get("texto", "").strip().lower()
    filas = [r for r in datos.listar("auditoria") if not q or q in f"{r['usuario']} {r['accion']} {r['detalle']} {r['modulo']}".lower()]
    return render_template("auditoria.html", filas=mas_reciente_primero(filas, "fecha_hora")[:300], q=q)


@app.get("/perfil")
@requiere()
def perfil():
    return render_template("perfil.html")


# ============================================ datos de ejemplo (solo local)
def datos_de_ejemplo():
    """Modo local, primera vez: crea un usuario por rol y unos casos de ejemplo marcados [PRUEBA]."""
    ids = {}
    for rol, correo, nombre in [("administrador", "admin@demo.local", "Ana Administradora"),
                                ("responsable_seguridad", "responsable@demo.local", "Rosa Responsable"),
                                ("tecnico", "tecnico@demo.local", "Tomás Técnico"),
                                ("auditor", "auditor@demo.local", "Alberto Auditor"),
                                ("gerencia", "gerencia@demo.local", "Gloria Gerencia")]:
        ids[rol] = crear_usuario({"nombre": nombre, "correo": correo, "rol": rol, "departamento": "TI", "clave": "Demo12345"})
    admin = datos.obtener("usuarios", ids["administrador"])
    a1 = datos.crear("activos", {"nombre": "Servidor de aplicaciones [PRUEBA]", "tipo": "Servidor", "ip": "10.0.0.10", "criticidad": "Crítica",
                                 "marca": "", "modelo": "", "serie": "", "sistema": "Ubuntu 22.04", "ubicacion": "Centro de datos",
                                 "responsable": "TI", "estado": "Activo", "fecha_registro": ahora()}, datos.nuevo_id("ACT"))
    a2 = datos.crear("activos", {"nombre": "Laptop de contabilidad [PRUEBA]", "tipo": "Laptop", "ip": "", "criticidad": "Media",
                                 "marca": "", "modelo": "", "serie": "", "sistema": "Windows 11", "ubicacion": "Oficina",
                                 "responsable": "Contabilidad", "estado": "Activo", "fecha_registro": ahora()}, datos.nuevo_id("ACT"))
    for titulo, act, sev in [("Versión de OpenSSL desactualizada [PRUEBA]", a1, "Crítica"),
                             ("Antivirus con licencia vencida [PRUEBA]", a2, "Media"),
                             ("Puerto de administración expuesto [PRUEBA]", a1, "Alta")]:
        vid = datos.crear("vulnerabilidades", {
            "titulo": titulo, "descripcion": "Dato de prueba para estudiar el sistema.", "tipo": "Software desactualizado",
            "fuente": "Reporte técnico interno", "fecha_deteccion": hoy(), "severidad": sev, "cve": "", "cvss": None,
            "id_activo": act, "justificacion": "", "estado": "Registrada", "registrado_por": admin["nombre"],
            "fecha_registro": ahora(), "veces_reabierta": 0}, datos.nuevo_id("VUL"))
        seguimiento(vid, admin, "Registro de la vulnerabilidad", "Dato de prueba", "Registrada")


if datos.MODO_LOCAL and not datos.hay_datos():
    datos_de_ejemplo()
    print("\n  Datos de ejemplo creados. Entra con  admin@demo.local  /  Demo12345\n")


if __name__ == "__main__":
    app.run(debug=not PRODUCCION, port=int(os.getenv("PORT", 5000)))
