/* Interacciones de la interfaz (sin dependencias, salvo Chart.js para las gráficas). */
(function () {
  "use strict";

  // Menú lateral en pantallas pequeñas
  var barra = document.getElementById("barra");
  var fondo = document.getElementById("fondo-menu");
  var boton = document.getElementById("abrir-menu");
  function menu(abrir) {
    if (!barra) return;
    barra.classList.toggle("abierta", abrir);
    if (fondo) fondo.classList.toggle("hidden", !abrir);
    if (boton) boton.setAttribute("aria-expanded", abrir ? "true" : "false");
  }
  if (boton) boton.addEventListener("click", function () { menu(!barra.classList.contains("abierta")); });
  if (fondo) fondo.addEventListener("click", function () { menu(false); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") menu(false); });

  // Confirmación antes de operaciones importantes: <form data-confirma="¿Seguro?">
  document.addEventListener("submit", function (e) {
    var texto = e.target.getAttribute && e.target.getAttribute("data-confirma");
    if (texto && !window.confirm(texto)) e.preventDefault();
  });

  // Validación visual básica: marca los campos vacíos u obligatorios antes de enviar
  document.querySelectorAll("form[data-valida]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      var primero = null;
      form.querySelectorAll(".campo").forEach(function (c) {
        var mal = !c.checkValidity();
        c.classList.toggle("invalido", mal);
        if (mal && !primero) primero = c;
      });
      if (primero) { e.preventDefault(); primero.reportValidity(); primero.focus(); }
    });
    form.addEventListener("input", function (e) { if (e.target.classList) e.target.classList.remove("invalido"); });
  });

  // Filtro de tabla en el navegador: <input data-filtra="id-de-la-tabla">
  document.querySelectorAll("input[data-filtra]").forEach(function (entrada) {
    entrada.addEventListener("input", function () {
      var t = document.getElementById(entrada.getAttribute("data-filtra"));
      var q = entrada.value.trim().toLowerCase();
      if (!t) return;
      t.querySelectorAll("tbody tr").forEach(function (fila) {
        fila.style.display = fila.textContent.toLowerCase().indexOf(q) === -1 ? "none" : "";
      });
    });
  });

  // Gráficas del dashboard: los datos vienen en data-datos (calculados en el servidor)
  var COLORES = { "Crítica": "#dc2626", "Alta": "#f97316", "Media": "#f59e0b", "Baja": "#16a34a" };
  var PALETA = ["#0f766e", "#2563eb", "#7c3aed", "#d97706", "#db2777", "#0891b2", "#65a30d", "#64748b"];
  function iniciarGraficas() {
    if (!window.Chart) return;
    window.Chart.defaults.font.family = "system-ui, sans-serif";
    document.querySelectorAll("canvas[data-grafica]").forEach(function (cv) {
      var tipo = cv.getAttribute("data-grafica");
      var datos = JSON.parse(cv.getAttribute("data-datos"));
      var opciones = { responsive: true, maintainAspectRatio: false };
      if (tipo === "linea") {
        new Chart(cv, { type: "line", options: opciones, data: { labels: datos.meses, datasets: [
          { label: "Registradas", data: datos.registradas, borderColor: "#0f766e", backgroundColor: "#0f766e", tension: .3 },
          { label: "Cerradas", data: datos.cerradas, borderColor: "#2563eb", backgroundColor: "#2563eb", tension: .3 }] } });
        return;
      }
      var etiquetas = Object.keys(datos), valores = etiquetas.map(function (k) { return datos[k]; });
      var colores = etiquetas.map(function (k, i) { return COLORES[k] || PALETA[i % PALETA.length]; });
      if (tipo === "dona") {
        new Chart(cv, { type: "doughnut", options: Object.assign({}, opciones, { plugins: { legend: { position: "right" } } }),
          data: { labels: etiquetas, datasets: [{ data: valores, backgroundColor: colores }] } });
      } else {
        var horizontal = tipo === "barras-h";
        if (tipo !== "dona") colores = etiquetas.map(function () { return "#0f766e"; });
        new Chart(cv, { type: "bar", options: Object.assign({}, opciones, { indexAxis: horizontal ? "y" : "x",
          plugins: { legend: { display: false } },
          scales: { [horizontal ? "x" : "y"]: { beginAtZero: true, ticks: { precision: 0 } } } }),
          data: { labels: etiquetas, datasets: [{ data: valores, backgroundColor: colores }] } });
      }
    });
  }
  window.addEventListener("load", iniciarGraficas);
})();
