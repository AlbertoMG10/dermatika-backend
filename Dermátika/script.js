const diagnosticOptions = document.querySelectorAll(".diagnostic-option input");
const diagnosticButton = document.querySelector("#diagnosticButton");
const progressBar = document.querySelector(".progress-bar i");
const progressValue = document.querySelector(".progress-value");

const diagnosticState = {
  leve: {
    button: "Continuar evaluación",
    progress: "33%",
    message: "Tu caso puede requerir un protocolo de control y prevención. El médico confirmará si necesitas tratamiento oral o una alternativa."
  },
  moderado: {
    button: "Continuar evaluación médica",
    progress: "66%",
    message: "Tu perfil puede ser compatible con un protocolo dermatológico más estructurado. Continúa para revisar antecedentes y seguridad."
  },
  severo: {
    button: "Continuar evaluación prioritaria",
    progress: "100%",
    message: "Tu caso merece revisión médica cuidadosa. Continúa para confirmar contraindicaciones, dosis posible y seguimiento."
  }
};

function updateDiagnostic(value) {
  const state = diagnosticState[value] || diagnosticState.leve;
  if (diagnosticButton) diagnosticButton.textContent = state.button;
  if (progressBar) progressBar.style.width = state.progress;
  if (progressValue) progressValue.textContent = state.progress;
}

diagnosticOptions.forEach((option) => {
  option.addEventListener("change", () => updateDiagnostic(option.value));
});

diagnosticButton?.addEventListener("click", () => {
  const selected = document.querySelector(".diagnostic-option input:checked")?.value || "leve";
  const existing = document.querySelector(".diagnostic-feedback");
  if (existing) existing.remove();

  const feedback = document.createElement("div");
  feedback.className = "diagnostic-feedback";
  const message = document.createElement("span");
  message.textContent = diagnosticState[selected].message;
  const cta = document.createElement("a");
  cta.className = "button";
  cta.href = "evaluacion.html";
  cta.textContent = "Iniciar evaluación médica";
  feedback.append(message, cta);
  diagnosticButton.insertAdjacentElement("afterend", feedback);
});

const navToggle = document.querySelector(".nav-toggle");
const nav = document.querySelector("#primaryNav");

navToggle?.addEventListener("click", () => {
  const isOpen = nav?.classList.toggle("is-open");
  navToggle.setAttribute("aria-expanded", String(Boolean(isOpen)));
});

nav?.querySelectorAll("a").forEach((link) => {
  link.addEventListener("click", () => {
    nav.classList.remove("is-open");
    navToggle?.setAttribute("aria-expanded", "false");
  });
});

const revealItems = document.querySelectorAll(".reveal");
if ("IntersectionObserver" in window) {
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        revealObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.14 });

  revealItems.forEach((element) => revealObserver.observe(element));
} else {
  revealItems.forEach((element) => element.classList.add("is-visible"));
}

const backToTop = document.querySelector(".back-to-top");
const conversionDock = document.querySelector(".conversion-dock");
window.addEventListener("scroll", () => {
  backToTop?.classList.toggle("is-visible", window.scrollY > 720);
  conversionDock?.classList.toggle("is-visible", window.scrollY > 560);
}, { passive: true });

backToTop?.addEventListener("click", () => {
  window.scrollTo({ top: 0, behavior: "smooth" });
});

document.querySelectorAll(".button").forEach((button) => {
  button.addEventListener("pointerdown", () => button.classList.add("is-pressed"));
  button.addEventListener("pointerup", () => button.classList.remove("is-pressed"));
  button.addEventListener("pointerleave", () => button.classList.remove("is-pressed"));
});
