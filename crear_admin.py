"""Crea el primer administrador en Firebase (Authentication + perfil en Firestore).

Uso:  python crear_admin.py      (con MODO_LOCAL=0 en el archivo .env)
"""
import getpass
import os

os.environ.setdefault("MODO_LOCAL", "0")

import app as sistema  # noqa: E402
import datos  # noqa: E402

if datos.MODO_LOCAL:
    raise SystemExit("En modo local ya existen usuarios de ejemplo. Para crear el administrador de Firebase pon MODO_LOCAL=0 en .env.")
if [u for u in datos.listar("usuarios") if u["rol"] == "administrador"]:
    raise SystemExit("Ya existe un administrador. Crea los demás usuarios desde el sistema (Usuarios y permisos).")

nombre = input("Nombre completo: ").strip()
correo = input("Correo: ").strip()
clave = getpass.getpass("Contraseña (mínimo 8 caracteres): ")
try:
    sistema.crear_usuario({"nombre": nombre, "correo": correo, "rol": "administrador", "departamento": "TI", "clave": clave})
    print("\nListo. Ya puedes entrar al sistema con ese correo y contraseña.")
except sistema.Error as e:
    raise SystemExit(f"No se pudo crear: {e}")
