document.addEventListener("DOMContentLoaded", () => {
  // Edit this single constant to change the animated homepage name.
  const NAME = "Mohanad Edrees aka db1M";
  const target = document.querySelector("[data-hero-name]");
  if (!target) return;

  target.textContent = NAME;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const wait = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

  const loop = async () => {
    while (true) {
      target.textContent = "";

      for (const character of NAME) {
        target.textContent += character;
        await wait(65);
      }

      await wait(1800);

      while (target.textContent.length) {
        target.textContent = target.textContent.slice(0, -1);
        await wait(40);
      }

      await wait(450);
    }
  };

  loop();
});
