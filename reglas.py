"""Reglas del sistema: roles, permisos, estados y prioridad. No usa base de datos."""

ROLES = {
    "administrador": "Administrador del sistema",
    "responsable_seguridad": "Responsable de seguridad",
    "tecnico": "Técnico de TI",
    "auditor": "Auditor",
    "gerencia": "Gerencia",
}

# El administrador controla todo, pero NO atiende casos (así quien verifica no es quien corrigió).
PERMISOS = {
    "administrador": {"usuarios", "auditoria", "activos", "registrar", "gestionar", "ver_todo", "reportes"},
    "responsable_seguridad": {"activos_ver", "registrar", "gestionar", "ver_todo", "reportes"},
    "tecnico": {"activos_ver", "atender"},
    "auditor": {"auditoria", "activos_ver", "ver_todo", "reportes"},
    "gerencia": {"ver_todo", "reportes"},
}


def puede(rol, permiso):
    p = PERMISOS.get(rol, set())
    return permiso in p or (permiso == "activos_ver" and "activos" in p)


TIPOS_ACTIVO = ["Computadora", "Laptop", "Servidor", "Aplicación", "Base de datos", "Router", "Switch",
                "Punto de acceso", "Otro"]
TIPOS_VULN = ["Software desactualizado", "Configuración incorrecta", "Permisos inadecuados",
              "Debilidad en aplicaciones", "Problemas de seguridad en sistemas operativos",
              "Configuración de red", "Otro"]
FUENTES = ["Reporte técnico interno", "Revisión autorizada", "Aviso de proveedor", "Reporte externo",
           "Otra fuente documentada"]
NIVELES = {"Baja": 1, "Media": 2, "Alta": 3, "Crítica": 4}
NIVELES_ORDEN = ["Crítica", "Alta", "Media", "Baja"]
PROBABILIDADES = {"Baja": 1, "Media": 2, "Alta": 3}

ESTADOS = ["Registrada", "Validada", "Clasificada", "Priorizada", "Asignada", "En atención",
           "Pendiente de verificación", "Resuelta", "Cerrada", "Reabierta"]
PENDIENTES = ["Registrada", "Validada", "Clasificada", "Priorizada", "Asignada"]
EN_ATENCION = ["En atención", "Pendiente de verificación", "Reabierta"]
ABIERTOS = PENDIENTES + EN_ATENCION

# accion: (estados de origen, estado nuevo o None, permiso, etiqueta)
ACCIONES = {
    "validar": ({"Registrada"}, "Validada", "gestionar", "Validar registro"),
    "clasificar": ({"Validada"}, "Clasificada", "gestionar", "Clasificar"),
    "priorizar": ({"Clasificada"}, "Priorizada", "gestionar", "Priorizar"),
    "asignar": ({"Priorizada", "Asignada", "En atención", "Reabierta"}, None, "gestionar", "Asignar / reasignar técnico"),
    "iniciar": ({"Asignada", "Reabierta"}, "En atención", "atender", "Iniciar atención"),
    "avance": ({"En atención"}, None, "atender", "Registrar avance"),
    "pedir_verificacion": ({"En atención"}, "Pendiente de verificación", "atender", "Solicitar verificación"),
    "aprobar": ({"Pendiente de verificación"}, "Resuelta", "gestionar", "Aprobar solución"),
    "rechazar": ({"Pendiente de verificación"}, "Reabierta", "gestionar", "Rechazar solución"),
    "cerrar": ({"Resuelta"}, "Cerrada", "gestionar", "Cerrar caso"),
    "reabrir": ({"Resuelta", "Cerrada"}, "Reabierta", "gestionar", "Reabrir caso"),
}


def acciones_disponibles(vuln, usuario):
    """Acciones que su rol permite en el estado actual (el técnico solo en sus casos)."""
    salida = []
    for nombre, (origen, _destino, permiso, _et) in ACCIONES.items():
        if vuln["estado"] not in origen or not puede(usuario["rol"], permiso):
            continue
        if permiso == "atender" and vuln.get("id_tecnico") != usuario["id"]:
            continue
        salida.append(nombre)
    return salida


def puede_ver(vuln, usuario):
    return puede(usuario["rol"], "ver_todo") or vuln.get("id_tecnico") == usuario["id"]


def sugerir_prioridad(severidad, criticidad_activo, impacto, probabilidad):
    """(severidad + criticidad del activo + impacto) x probabilidad. 24+ Crítica, 15-23 Alta, 8-14 Media, <8 Baja."""
    puntaje = (NIVELES[severidad] + NIVELES[criticidad_activo] + NIVELES[impacto]) * PROBABILIDADES[probabilidad]
    nivel = "Crítica" if puntaje >= 24 else "Alta" if puntaje >= 15 else "Media" if puntaje >= 8 else "Baja"
    return puntaje, nivel
