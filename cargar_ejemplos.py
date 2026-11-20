"""Llena el sistema con datos de ejemplo (todo marcado [PRUEBA]) para entender cómo funciona.

Uso:
    python cargar_ejemplos.py             crea usuarios, activos y vulnerabilidades de ejemplo
    python cargar_ejemplos.py --limpiar   borra SOLO lo que creó este script

Funciona en Firebase (MODO_LOCAL=0 en .env, con clave-firebase.json) y también en modo local.
Los casos se mueven con las mismas reglas del sistema (aplicar_accion), así que el historial,
las evaluaciones, asignaciones, verificaciones y la auditoría quedan igual que si los hicieras a mano.
"""
import getpass
import os
import sys
from datetime import date, datetime, timedelta

import app as sistema
import datos

DOMINIO = "@ejemplo.sgv"
MARCA = "[PRUEBA]"
USUARIOS = [
    ("administrador", "Ana Administradora", "admin"),
    ("responsable_seguridad", "Rosa Responsable", "responsable"),
    ("tecnico", "Tomás Técnico", "tecnico1"),
    ("tecnico", "Teresa Técnica", "tecnico2"),
    ("auditor", "Alberto Auditor", "auditor"),
    ("gerencia", "Gloria Gerencia", "gerencia"),
]
# nombre, tipo, ip, criticidad, sistema, ubicación, responsable
ACTIVOS = [
    ("Servidor de aplicaciones", "Servidor", "10.0.0.10", "Crítica", "Ubuntu 22.04", "Centro de datos", "TI"),
    ("Base de datos de clientes", "Base de datos", "10.0.0.20", "Crítica", "PostgreSQL 14", "Centro de datos", "TI"),
    ("Router principal", "Router", "10.0.0.1", "Alta", "Firmware 3.2", "Site de comunicaciones", "Redes"),
    ("Sistema de nómina", "Aplicación", "", "Alta", "Aplicación web", "Nube", "Recursos Humanos"),
    ("Laptop de contabilidad", "Laptop", "10.0.1.35", "Media", "Windows 11", "Oficina", "Contabilidad"),
    ("PC de recepción", "Computadora", "10.0.1.50", "Baja", "Windows 10", "Recepción", "Administración"),
    ("Punto de acceso piso 2", "Punto de acceso", "10.0.2.5", "Media", "Firmware 1.8", "Piso 2", "Redes"),
    ("Switch principal", "Switch", "10.0.0.2", "Alta", "Firmware 5.1", "Site de comunicaciones", "Redes"),
]
# título, tipo, fuente, severidad, índice del activo, cvss, cve, días desde la detección, pasos
# pasos: "accion" o "accion:dato:dato". asignar:T1:+N  -> técnico 1, fecha límite en N días (negativo = vencida)
VULNS = [
    ("Versión de OpenSSL desactualizada", "Software desactualizado", "Revisión autorizada", "Crítica", 0, 9.1, "CVE-2022-0778", 25,
     ["validar", "clasificar:Crítica:Alta", "priorizar:Crítica", "asignar:T1:-3", "iniciar", "avance"]),            # vencida
    ("Contraseña de administrador por defecto", "Configuración incorrecta", "Reporte técnico interno", "Alta", 2, 8.1, "", 20,
     ["validar", "clasificar:Alta:Alta", "priorizar:Alta", "asignar:T2:+2", "iniciar"]),                           # próxima a vencer
    ("Puerto de administración expuesto a internet", "Configuración de red", "Revisión autorizada", "Alta", 0, 7.5, "", 18,
     ["validar", "clasificar:Alta:Media", "priorizar:Alta", "asignar:T1:+10", "iniciar", "avance", "pedir_verificacion"]),
    ("Antivirus con licencia vencida", "Software desactualizado", "Reporte técnico interno", "Media", 4, 5.0, "", 14,
     ["validar", "clasificar:Media:Media", "priorizar:Media", "asignar:T2:+15", "iniciar", "pedir_verificacion", "aprobar"]),
    ("Permisos excesivos en carpeta de nómina", "Permisos inadecuados", "Revisión autorizada", "Alta", 3, 6.8, "", 40,
     ["validar", "clasificar:Alta:Alta", "priorizar:Alta", "asignar:T1:+5", "iniciar", "pedir_verificacion", "aprobar", "cerrar"]),
    ("Firmware del router sin actualizar", "Software desactualizado", "Aviso de proveedor", "Alta", 2, 7.2, "CVE-2023-1389", 30,
     ["validar", "clasificar:Alta:Alta", "priorizar:Crítica", "asignar:T2:+7", "iniciar", "pedir_verificacion", "aprobar", "cerrar"]),
    ("Respaldo sin cifrar en la base de datos", "Configuración incorrecta", "Reporte técnico interno", "Alta", 1, 6.5, "", 12,
     ["validar", "clasificar:Alta:Alta", "priorizar:Alta", "asignar:T1:+8", "iniciar", "pedir_verificacion", "rechazar"]),
    ("Sistema operativo sin parches de seguridad", "Problemas de seguridad en sistemas operativos", "Revisión autorizada", "Media", 5, 5.5, "", 35,
     ["validar", "clasificar:Media:Baja", "priorizar:Media", "asignar:T2:+6", "iniciar", "pedir_verificacion", "aprobar", "cerrar", "reabrir"]),
    ("Red inalámbrica con cifrado débil", "Configuración de red", "Reporte externo", "Media", 6, 5.3, "", 6,
     ["validar", "clasificar:Media:Media", "priorizar:Media"]),
    ("Formulario web sin validación de datos", "Debilidad en aplicaciones", "Revisión autorizada", "Media", 3, 5.9, "", 4,
     ["validar", "clasificar:Media:Media"]),
    ("Cuenta de usuario ex-empleado sigue activa", "Permisos inadecuados", "Reporte técnico interno", "Baja", 7, None, "", 3,
     ["validar"]),
    ("Servicio Telnet habilitado en el switch", "Configuración de red", "Reporte técnico interno", "Alta", 7, 7.0, "", 2, []),
    ("Cable de red expuesto en recepción", "Otro", "Otra fuente documentada", "Baja", 5, None, "", 1, []),
]


def conocidos():
    return [u for u in datos.listar("usuarios") if u["correo"].endswith(DOMINIO)]


def limpiar():
    uids = [u["id"] for u in conocidos()]
    n = 0
    for v in datos.listar("vulnerabilidades"):
        if MARCA in v["titulo"]:
            for col in ("evaluaciones", "asignaciones", "seguimientos", "verificaciones", "evidencias"):
                for d in datos.listar(col, id_vulnerabilidad=v["id"]):
                    datos.eliminar(col, d["id"])
            datos.eliminar("vulnerabilidades", v["id"])
            n += 1
    for a in datos.listar("activos"):
        if MARCA in a["nombre"]:
            datos.eliminar("activos", a["id"])
    for uid in uids:
        if not datos.MODO_LOCAL:
            from firebase_admin import auth
            try:
                auth.delete_user(uid)
            except Exception as e:
                print(f"  (aviso) no se pudo borrar la cuenta {uid}: {e}")
        datos.eliminar("usuarios", uid)
    print(f"Listo: se borraron {n} vulnerabilidades, los activos de ejemplo y {len(uids)} usuarios de ejemplo.")
    print("La bitácora de auditoría se conserva (es un registro histórico).")


def cargar():
    if conocidos():
        raise SystemExit(f"Ya hay usuarios de ejemplo ({DOMINIO}). Ejecuta primero:  python cargar_ejemplos.py --limpiar")
    print("Se crearán usuarios de ejemplo con el dominio", DOMINIO)
    clave = os.getenv("CLAVE_EJEMPLOS") or getpass.getpass("Contraseña para TODOS los usuarios de ejemplo (mínimo 8 caracteres): ")
    if len(clave) < 8:
        raise SystemExit("La contraseña debe tener al menos 8 caracteres.")

    us = {}
    for rol, nombre, alias in USUARIOS:
        uid = sistema.crear_usuario({"nombre": nombre, "correo": alias + DOMINIO, "rol": rol,
                                     "departamento": "TI", "clave": clave})
        us[alias] = datos.obtener("usuarios", uid)
    resp = us["responsable"]
    tec = {"T1": us["tecnico1"], "T2": us["tecnico2"]}

    ids_act = []
    for n, tipo, ip, crit, so, ubi, resp_a in ACTIVOS:
        ids_act.append(datos.crear("activos", {
            "nombre": f"{n} {MARCA}", "tipo": tipo, "marca": "", "modelo": "", "serie": "", "sistema": so, "ip": ip,
            "ubicacion": ubi, "responsable": resp_a, "criticidad": crit, "estado": "Activo",
            "fecha_registro": sistema.ahora()}, datos.nuevo_id("ACT")))

    for i, (tit, tipo, fuente, sev, ia, cvss, cve, dias, ruta) in enumerate(VULNS, 1):
        v = {"titulo": f"{tit} {MARCA}", "descripcion": "Caso de ejemplo para estudiar cómo funciona el sistema.",
             "tipo": tipo, "fuente": fuente, "fecha_deteccion": (date.today() - timedelta(days=dias)).isoformat(),
             "severidad": sev, "cve": cve, "cvss": cvss, "id_activo": ids_act[ia], "justificacion": "",
             "estado": "Registrada", "registrado_por": resp["nombre"],
             "fecha_registro": (datetime.now() - timedelta(days=dias)).isoformat(timespec="microseconds"),
             "veces_reabierta": 0}
        vid = datos.crear("vulnerabilidades", v, datos.nuevo_id("VUL"))
        sistema.seguimiento(vid, resp, "Registro de la vulnerabilidad", "Caso de ejemplo", "Registrada")
        sistema.registrar(resp, "Registro de vulnerabilidad", "Vulnerabilidades", vid, detalle=tit)
        for paso in ruta:
            accion, *p = paso.split(":")
            f, actor, limite = {}, resp, None
            if accion == "clasificar":
                f = {"impacto": p[0], "probabilidad": p[1]}
            elif accion == "priorizar":
                f = {"prioridad": p[0], "justificacion": "Se prioriza según el puntaje y la criticidad del activo."}
            elif accion == "asignar":
                limite = (date.today() + timedelta(days=int(p[1]))).isoformat()
                # el sistema rechaza fechas pasadas: se asigna a mañana y después se ajusta (para simular un retraso)
                f = {"id_tecnico": tec[p[0]]["id"], "observaciones": "Atender con la prioridad indicada.",
                     "fecha_limite": max(limite, (date.today() + timedelta(days=1)).isoformat())}
            elif accion in ("iniciar", "avance", "pedir_verificacion"):
                actor = datos.obtener("usuarios", datos.obtener("vulnerabilidades", vid)["id_tecnico"])
                f = {"actividad": "Se avanzó con la revisión de la configuración." if accion == "avance"
                     else "Se revisó el problema y se aplicó la corrección.",
                     "evidencia": "Captura de la configuración corregida (ejemplo).", "observaciones": "Sin novedades."}
            elif accion == "aprobar":
                f = {"observaciones": "Se comprobó que la vulnerabilidad ya no existe."}
            elif accion == "rechazar":
                f = {"observaciones": "La corrección no es suficiente: el problema sigue presente."}
            elif accion == "cerrar":
                f = {"observaciones": "Caso cerrado."}
            elif accion == "reabrir":
                f = {"observaciones": "El problema volvió a aparecer tras una actualización."}
            sistema.aplicar_accion(datos.obtener("vulnerabilidades", vid), actor, accion, f)
            if limite and limite != f["fecha_limite"]:
                datos.actualizar("vulnerabilidades", vid, {"fecha_limite": limite})
                for a in datos.listar("asignaciones", id_vulnerabilidad=vid, estado="Vigente"):
                    datos.actualizar("asignaciones", a["id"], {"fecha_limite": limite})
        print(f"  {i:>2}. {tit[:55]:<55} → {datos.obtener('vulnerabilidades', vid)['estado']}")

    print(f"\nListo: {len(USUARIOS)} usuarios, {len(ACTIVOS)} activos y {len(VULNS)} vulnerabilidades de ejemplo.")
    print(f"Entra con  admin{DOMINIO}  y la contraseña que escribiste.")
    print("Otros usuarios (mismo dominio y contraseña): responsable, tecnico1, tecnico2, auditor, gerencia.")


if __name__ == "__main__":
    if "--limpiar" in sys.argv:
        limpiar()
    else:
        cargar()
