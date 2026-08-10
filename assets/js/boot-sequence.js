document.addEventListener("DOMContentLoaded", () => {
  const overlay = document.getElementById("boot-sequence");
  if (!overlay) return;

  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (prefersReduced) {
    overlay.remove();
    document.documentElement.classList.remove("boot-sequence-pending");
    document.documentElement.classList.add("boot-sequence-skip");
    return;
  }

  const canvas = overlay.querySelector(".boot-sequence__matrix");
  const terminal = overlay.querySelector("[data-boot-terminal]");
  const ctx = canvas.getContext("2d");
  const columns = { width: 16, fontSize: 13, drops: [] };
  let frameId = 0;

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const total = Math.ceil(canvas.width / columns.width);
    columns.drops = Array.from({ length: total }, () => Math.floor(Math.random() * (canvas.height / columns.fontSize)));
  }

  function drawMatrix() {
    ctx.fillStyle = "rgba(7,13,18,0.15)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = `${columns.fontSize}px "JetBrains Mono", "Fira Code", monospace`;

    columns.drops.forEach((drop, index) => {
      const char = Math.random() < 0.5 ? "0" : "1";
      ctx.fillStyle = Math.random() < 0.1 ? "rgba(142,247,209,0.25)" : "rgba(31,110,86,0.18)";
      ctx.fillText(char, index * columns.width, drop * columns.fontSize);

      if (drop * columns.fontSize > canvas.height && Math.random() < 0.025) {
        columns.drops[index] = 0;
      } else {
        columns.drops[index] = drop + 1;
      }
    });

    frameId = window.requestAnimationFrame(drawMatrix);
  }

  const lines = [
    "./db1M.sh",
    "initializing db1M.sh...",
    "loading exploits... done",
    "ready.",
  ];
  const typeDelay = 28;
  const linePause = 220;
  const holdDelay = 500;
  const fadeDelay = 400;

  function sleep(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
  }

  async function typeLines() {
    for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
      const row = document.createElement("p");
      row.className = lineIndex === 0 ? "boot-sequence__line boot-sequence__line--first" : "boot-sequence__line";

      const prefix = document.createElement("span");
      prefix.className = "boot-sequence__prefix";

      const text = document.createElement("span");
      text.className = "boot-sequence__text";

      const cursor = document.createElement("span");
      cursor.className = "boot-sequence__cursor";
      cursor.textContent = "_";

      row.append(prefix, text, cursor);
      terminal.append(row);

      for (const char of "$ ") {
        prefix.textContent += char;
        await sleep(typeDelay);
      }

      for (const char of lines[lineIndex]) {
        text.textContent += char;
        await sleep(typeDelay);
      }

      cursor.remove();
      if (lineIndex < lines.length - 1) await sleep(linePause);
    }

    await sleep(holdDelay);
    overlay.classList.add("is-fading");
    await sleep(fadeDelay);
    window.cancelAnimationFrame(frameId);
    window.removeEventListener("resize", resizeCanvas);
    overlay.remove();
    document.documentElement.classList.remove("boot-sequence-pending");
    document.documentElement.classList.add("boot-sequence-skip");
  }

  resizeCanvas();
  window.addEventListener("resize", resizeCanvas);
  drawMatrix();
  typeLines();
});
