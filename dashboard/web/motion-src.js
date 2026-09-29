// Motion's DOM API keeps the existing accessible HTML and analyzer UI intact.
import { animate } from "motion/mini";

const motionTokens = {
  duration: {fast: 0.18, normal: 0.35, slow: 0.6},
  easing: {smooth: [0.22, 1, 0.36, 1]},
  distance: {sm: 8, md: 16},
};

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const lowEnd = navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 4;
function enter(element, delay = 0, distance = motionTokens.distance.sm) {
  if (!element) return;
  animate(element, {
    opacity: [0, 1],
    transform: [`translateY(${distance}px)`, "translateY(0px)"],
  }, {
    duration: motionTokens.duration.normal,
    delay,
    ease: motionTokens.easing.smooth,
  });
}

if (!reduceMotion.matches && !lowEnd) {
  enter(document.querySelector(".page-heading"), 0, motionTokens.distance.md);
  document.querySelectorAll(".empty-guide > div").forEach((item, index) =>
    enter(item, motionTokens.duration.fast + index * 0.07));
}

window.addEventListener("ipsec:status", () => {
  if (reduceMotion.matches) return;
  const status = document.getElementById("status");
  animate(status, {opacity: [0.55, 1]}, {duration: motionTokens.duration.fast});
});

window.addEventListener("ipsec:results", () => {
  if (reduceMotion.matches || lowEnd) return;
  enter(document.querySelector(".provenance-rail"));
  document.querySelectorAll(".summary-strip .metric").forEach((item, index) =>
    enter(item, motionTokens.duration.fast + index * 0.06));
  enter(document.querySelector(".content-grid"), motionTokens.duration.normal);
});
