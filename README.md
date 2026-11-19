# SGV · Gestión de Vulnerabilidades (versión simple)

Sistema para **Servicios Empresariales del Centro, S.A. de C.V.** (empresa ficticia). Gestiona vulnerabilidades
ya identificadas: no escanea ni explota equipos. Hecho con Python + Flask, HTML, Tailwind CSS (ya compilado) y Firebase.

Solo hay **3 archivos de Python**: `datos.py` (guarda datos), `reglas.py` (roles, estados, prioridad) y `app.py` (pantallas y lógica).

---

## 1. Correrlo ya (sin Firebase)

Necesitas Python 3.10 o mayor. En una terminal, dentro de esta carpeta:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
(En Windows, si `python` no funciona, usa `py`.)

Abre **http://127.0.0.1:5000** y entra con:

| Correo | Rol | Contraseña |
|---|---|---|
| admin@demo.local | Administrador | Demo12345 |
| responsable@demo.local | Responsable de seguridad | Demo12345 |
| tecnico@demo.local | Técnico de TI | Demo12345 |
| auditor@demo.local | Auditor | Demo12345 |
| gerencia@demo.local | Gerencia | Demo12345 |

La primera vez se crean solos estos usuarios y 3 casos «[PRUEBA]». Todo se guarda en `datos_local.json`.

**Si no te deja entrar:** cierra el programa, **borra `datos_local.json`** (y la carpeta `archivos_local` si existe) y vuelve a
ejecutar `python app.py`. Se crean de nuevo los usuarios de arriba. Lo más común es tener un `datos_local.json` viejo de otra versión.

Pruebas (opcional): `pip install pytest` y `python -m pytest -q`.

---

## 2. Conectarlo con Firebase (30 minutos)

### A. Crear el proyecto y activar servicios
1. <https://console.firebase.google.com> → **Agregar proyecto**.
2. **Authentication** → Comenzar → habilita **Correo electrónico/contraseña**.
3. **Firestore Database** → Crear base de datos → modo **producción** → región `us-central1`.
4. **Storage** → Comenzar → modo producción. Anota el nombre del bucket (ej. `mi-proyecto.firebasestorage.app`).
5. Para producción (paso 3) necesitas el plan **Blaze**; pon una alerta de presupuesto de 5 USD en Google Cloud.

### B. Pegar la configuración web
Consola → ⚙ **Configuración del proyecto → General → Tus apps → icono `</>`** (app web). Copia `apiKey`, `authDomain`,
`projectId` y `appId` y pégalos en **`static/firebase-config.js`**. (Esos datos son públicos por diseño; no son secretos.)

### C. Descargar la clave del servidor
⚙ **Configuración del proyecto → Cuentas de servicio → Generar nueva clave privada**. Guarda el `.json` **fuera** de esta
carpeta (por ejemplo `C:\claves\sgv.json`). Es una clave secreta: no la subas a Git ni la compartas.

### D. Crear tu archivo `.env`
Copia `.env.example` como `.env` y llénalo:
```ini
MODO_LOCAL=0
SECRET_KEY=<resultado de: python -c "import secrets; print(secrets.token_hex(32))">
STORAGE_BUCKET=mi-proyecto.firebasestorage.app
GOOGLE_APPLICATION_CREDENTIALS=C:\claves\sgv.json
```

### E. Crear el administrador y arrancar
```bash
python crear_admin.py     # te pide nombre, correo y contraseña
python app.py
```
Abre http://127.0.0.1:5000 e inicia sesión con ese correo. Desde **Usuarios y permisos** crea a los demás usuarios.

✅ Comprobación: registra un activo y una vulnerabilidad y míralos aparecer en Firebase → Firestore → Datos
(`activos`, `vulnerabilidades`, `seguimientos`, `auditoria`).

### F. (Recomendado) Publicar las reglas de seguridad
Niegan todo acceso directo desde el navegador; solo el servidor entra:
```bash
npm install -g firebase-tools
firebase login
firebase use --add
firebase deploy --only firestore:rules,storage
```

---

## 3. Ponerlo en producción (Cloud Run, un comando)

Instala [gcloud](https://cloud.google.com/sdk/docs/install), entra con `gcloud auth login` y elige tu proyecto
(`gcloud config set project ID_DEL_PROYECTO`). Una sola vez, habilita las APIs y da permisos a la cuenta de Cloud Run
(el número del proyecto está en la consola de Google Cloud):

```bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
SA=NUMERO_DEL_PROYECTO-compute@developer.gserviceaccount.com
for R in roles/datastore.user roles/firebaseauth.admin roles/storage.objectAdmin; do
  gcloud projects add-iam-policy-binding ID_DEL_PROYECTO --member="serviceAccount:$SA" --role="$R"
done
```

Y para publicar (y para cada actualización futura):

```bash
gcloud run deploy sgv --source . --region us-central1 --allow-unauthenticated \
  --set-env-vars "ENTORNO=produccion,MODO_LOCAL=0,STORAGE_BUCKET=mi-proyecto.firebasestorage.app,SECRET_KEY=<tu clave>"
```
Te imprime una dirección `https://sgv-xxxx.run.app`: esa es tu aplicación, ya con HTTPS. No uses `GOOGLE_APPLICATION_CREDENTIALS` allí.
Si el inicio de sesión da `auth/unauthorized-domain`, agrega ese dominio en Authentication → Configuración → Dominios autorizados.

Firebase Hosting es opcional (no hace falta para que funcione).

## Problemas frecuentes
| Síntoma | Solución |
|---|---|
| «Falta pegar la configuración de Firebase» | Completa `static/firebase-config.js` (paso 2B) |
| `DefaultCredentialsError` | Revisa `GOOGLE_APPLICATION_CREDENTIALS` (ruta completa al .json) |
| «Tu cuenta no tiene acceso al sistema» | El usuario existe en Authentication pero no en el sistema: créalo en *Usuarios y permisos* o con `crear_admin.py` |
| `403 Permission denied` en Cloud Run | Falta algún rol del paso 3 |
| `RuntimeError: Falta la variable SECRET_KEY` | Agrégala en `.env` (o en `--set-env-vars`) |
| Subida de archivos rechazada | Solo PDF, imágenes, TXT, CSV, LOG, DOCX, XLSX de máximo 5 MB |

## Qué incluye
Usuarios y 5 roles (el administrador controla todo pero no atiende casos) · activos · vulnerabilidades con su ciclo
(Registrada → Validada → Clasificada → Priorizada → Asignada → En atención → Pendiente de verificación → Resuelta → Cerrada / Reabierta)
· prioridad sugerida · asignación con fecha límite · historial · evidencias privadas · alertas en el dashboard (no se envían correos)
· gráficas · CSV · auditoría. Los permisos se verifican en el servidor.

**Cambiar estilos:** `static/app.css` ya está compilado. Solo si modificas las plantillas: `npm i tailwindcss@3.4.17` y
`npx tailwindcss -c tailwind.config.js -i estilos/entrada.css -o static/app.css --minify`.
