// Tailwind solo genera las clases que aparecen en estos archivos.
module.exports = {
  content: ["./templates/**/*.html", "./static/*.js"],
  // Las etiquetas de color se arman con nombres dinámicos en las plantillas (macros), por eso se listan aquí.
  safelist: [{ pattern: /^(nivel-(critica|alta|media|baja)|estado-(gris|azul|ambar|violeta|verde|rojo))$/ }],
  theme: { extend: {} },
  plugins: [],
};
