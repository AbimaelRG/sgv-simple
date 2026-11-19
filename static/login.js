// Inicio de sesión con Firebase Authentication (solo cuando MODO_LOCAL=0).
// 1) El navegador valida correo y contraseña con Firebase y recibe un token.
// 2) Se lo manda a /sesion; el servidor lo verifica y crea su propia sesión.
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, signOut } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { firebaseConfig } from "./firebase-config.js";

const form = document.getElementById("form-login");
const aviso = document.getElementById("mensaje-login");
const boton = document.getElementById("boton-login");
const csrf = form.querySelector("[name=csrf]").value;
const mostrar = (t) => { aviso.textContent = t; aviso.classList.remove("hidden"); };

if (firebaseConfig.apiKey === "PEGA_AQUI") {
  mostrar("Falta pegar la configuración de Firebase en static/firebase-config.js (ver README).");
  boton.disabled = true;
} else {
  const auth = getAuth(initializeApp(firebaseConfig));
  const MENSAJES = {
    "auth/invalid-credential": "Correo o contraseña incorrectos.",
    "auth/user-disabled": "Tu cuenta está desactivada.",
    "auth/too-many-requests": "Demasiados intentos. Espera unos minutos.",
    "auth/network-request-failed": "Sin conexión con Firebase.",
  };
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    aviso.classList.add("hidden");
    if (!form.correo.value || !form.clave.value) return mostrar("Escribe tu correo y tu contraseña.");
    boton.disabled = true; boton.textContent = "Entrando…";
    try {
      const cred = await signInWithEmailAndPassword(auth, form.correo.value.trim(), form.clave.value);
      const resp = await fetch("/sesion", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ idToken: await cred.user.getIdToken() }),
      });
      const datos = await resp.json().catch(() => ({}));
      await signOut(auth);                 // la sesión la guarda el servidor, no el navegador
      if (!resp.ok) throw { servidor: datos.error };
      window.location.href = "/panel";
    } catch (err) {
      mostrar(err.servidor || MENSAJES[err.code] || "No se pudo iniciar sesión.");
      boton.disabled = false; boton.textContent = "Entrar";
    }
  });
}
