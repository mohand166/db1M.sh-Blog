document.addEventListener("DOMContentLoaded", () => {
  const terminal = document.querySelector("[data-field-terminal]");
  if (!terminal || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const lines = [...terminal.querySelectorAll("[data-terminal-line]")];
  const wait = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

  const typeText = async (element, text) => {
    element.textContent = "";
    for (const character of text) {
      element.textContent += character;
      await wait(48 + Math.random() * 42);
    }
  };

  const play = async () => {
    while (true) {
      lines.forEach((line) => {
        line.hidden = true;
        line.classList.remove("is-typing", "is-complete");
        const text = line.querySelector("[data-terminal-text]");
        text.textContent = "";
      });

      await wait(450);

      for (const line of lines) {
        const text = line.querySelector("[data-terminal-text]");
        const value = text.dataset.terminalText;
        line.hidden = false;
        line.classList.add("is-typing");

        if (line.hasAttribute("data-terminal-output")) {
          await wait(260);
          text.textContent = value;
        } else {
          await typeText(text, value);
        }

        line.classList.remove("is-typing");
        await wait(line.hasAttribute("data-terminal-output") ? 650 : 180);
      }

      lines.at(-1).classList.add("is-complete");
      await wait(5000);
    }
  };

  play();
});
