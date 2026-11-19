"""Datos y archivos. Dos modos, la misma interfaz:

  MODO_LOCAL=1 -> todo en el archivo datos_local.json (para probar sin Firebase)
  MODO_LOCAL=0 -> Cloud Firestore y Firebase Storage

Funciones: listar, obtener, crear, actualizar, nuevo_id, guardar_archivo, leer_archivo, borrar_archivo.
"""
import json
import os
import re
import threading
import uuid

from dotenv import load_dotenv

load_dotenv()

AQUI = os.path.dirname(os.path.abspath(__file__))
MODO_LOCAL = os.getenv("MODO_LOCAL", "1") == "1"
STORAGE_BUCKET = os.getenv("STORAGE_BUCKET", "")
RUTA_JSON = os.path.join(AQUI, "datos_local.json")
CARPETA_ARCHIVOS = os.path.join(AQUI, "archivos_local")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_candado = threading.RLock()


def nuevo_id(prefijo):
    return f"{prefijo}-{uuid.uuid4().hex[:8].upper()}"


def _iniciar_firebase():
    import firebase_admin
    from firebase_admin import credentials
    if not firebase_admin._apps:
        ruta = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if not ruta or not os.path.exists(ruta):
            secreto_render = "/etc/secrets/clave-firebase.json"
            if os.path.exists(secreto_render):
                ruta = secreto_render
        cred = credentials.Certificate(ruta) if (ruta and os.path.exists(ruta)) else credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred, {"storageBucket": STORAGE_BUCKET} if STORAGE_BUCKET else None)


if not MODO_LOCAL:
    from firebase_admin import firestore
    _iniciar_firebase()
    _fs = firestore.client()


def _leer():
    if not os.path.exists(RUTA_JSON):
        return {}
    with open(RUTA_JSON, encoding="utf-8") as f:
        return json.load(f)


def _escribir(todo):
    with open(RUTA_JSON, "w", encoding="utf-8") as f:
        json.dump(todo, f, ensure_ascii=False, indent=2)


def hay_datos():
    return bool(_leer().get("usuarios")) if MODO_LOCAL else True


def listar(coleccion, **filtros):
    """Todos los documentos de la colección; los filtros son igualdades (campo=valor)."""
    if MODO_LOCAL:
        with _candado:
            docs = _leer().get(coleccion, {})
        filas = [{**d, "id": i} for i, d in docs.items()]
        return [f for f in filas if all(f.get(k) == v for k, v in filtros.items())]
    from google.cloud.firestore_v1.base_query import FieldFilter
    q = _fs.collection(coleccion)
    for campo, valor in filtros.items():
        q = q.where(filter=FieldFilter(campo, "==", valor))
    return [{**d.to_dict(), "id": d.id} for d in q.stream()]


def obtener(coleccion, doc_id):
    if not doc_id or not _ID.match(str(doc_id)):
        return None
    if MODO_LOCAL:
        with _candado:
            d = _leer().get(coleccion, {}).get(doc_id)
        return {**d, "id": doc_id} if d else None
    d = _fs.collection(coleccion).document(doc_id).get()
    return {**d.to_dict(), "id": d.id} if d.exists else None


def crear(coleccion, doc, doc_id=None):
    doc_id = doc_id or nuevo_id(coleccion[:3].upper())
    doc = {k: v for k, v in doc.items() if k != "id"}
    if MODO_LOCAL:
        with _candado:
            todo = _leer()
            todo.setdefault(coleccion, {})[doc_id] = doc
            _escribir(todo)
    else:
        _fs.collection(coleccion).document(doc_id).set(doc)
    return doc_id


def actualizar(coleccion, doc_id, cambios):
    cambios = {k: v for k, v in cambios.items() if k != "id"}
    if MODO_LOCAL:
        with _candado:
            todo = _leer()
            todo[coleccion][doc_id].update(cambios)
            _escribir(todo)
    else:
        _fs.collection(coleccion).document(doc_id).update(cambios)


# ---------------------------------------------------------------- archivos
def _local(ruta):
    destino = os.path.normpath(os.path.join(CARPETA_ARCHIVOS, ruta))
    if not destino.startswith(os.path.normpath(CARPETA_ARCHIVOS)):
        raise ValueError("Ruta no válida")
    return destino


def guardar_archivo(ruta, contenido, mime):
    if MODO_LOCAL:
        os.makedirs(os.path.dirname(_local(ruta)), exist_ok=True)
        with open(_local(ruta), "wb") as f:
            f.write(contenido)
    else:
        from firebase_admin import storage
        storage.bucket().blob(ruta).upload_from_string(contenido, content_type=mime)


def leer_archivo(ruta):
    if MODO_LOCAL:
        with open(_local(ruta), "rb") as f:
            return f.read()
    from firebase_admin import storage
    return storage.bucket().blob(ruta).download_as_bytes()