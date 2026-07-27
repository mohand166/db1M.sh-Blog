document.addEventListener("DOMContentLoaded", () => {
  const menu = document.querySelector("#fullscreen-navigation");
  const openButtons = [...document.querySelectorAll("[data-fullscreen-menu-open]")];
  const input = menu?.querySelector("[data-term-input]");
  const feedback = menu?.querySelector("[data-term-feedback]");
  const endpointButtons = [...(menu?.querySelectorAll("[data-term-endpoint]") || [])];
  const utcStatus = menu?.querySelector("[data-utc-status]");
  const acBox = menu?.querySelector("[data-term-autocomplete]");
  if (!menu || !openButtons.length || !input) return;

  const endpoints = endpointButtons.map((btn, i) => {
    const route = btn.getAttribute("data-term-endpoint") || "/";
    return {
      label: btn.textContent.trim(),
      route: route.startsWith("/") ? route : `/${route}`,
      element: btn,
      index: i,
    };
  });

  const SEARCH_HINT = "search for writeups, labs, keywords\u2026";

  /* ── help text ── */
  const HELP_TEXT = [
    "AVAILABLE COMMANDS:",
    "  cd {section}   \u2192  navigate to a section",
    "  cd              \u2192  go to home (/)",
    "  /               \u2192  open search modal",
    "  {keyword}       \u2192  search write-ups by keyword",
    "  ?               \u2192  show this help",
    "",
    "SECTIONS: " + endpoints.map((e) => e.label).join(", "),
  ].join("\n");

  /* ── search history (localStorage) ── */
  const HISTORY_KEY = "term_search_history";
  const MAX_HISTORY = 8;

  const loadHistory = () => {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch {
      return [];
    }
  };

  const saveHistory = (query) => {
    const q = query.trim();
    if (!q) return;
    let history = loadHistory().filter((h) => h !== q);
    history.unshift(q);
    if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  };

  const removeHistory = (query) => {
    const history = loadHistory().filter((h) => h !== query);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  };

  const clearHistory = () => {
    localStorage.removeItem(HISTORY_KEY);
  };

  /* ── page index cache ── */
  let pageIndex = null;

  const fetchPageIndex = async () => {
    if (pageIndex) return pageIndex;
    try {
      const res = await fetch((window.location.pathname.includes("/posts/") ? "../../" : "../") + "index.json");
      if (!res.ok) return [];
      const data = await res.json();
      pageIndex = data.map((item) => ({
        title: item.title || "",
        description: item.description || "",
        permalink: item.permalink || item.url || "",
        content: (item.content || "").slice(0, 600),
      }));
    } catch {
      pageIndex = [];
    }
    return pageIndex;
  };

  const searchPages = (query) => {
    if (!pageIndex) return [];
    const q = query.toLowerCase();
    return pageIndex.filter(
      (p) =>
        p.title.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.content.toLowerCase().includes(q)
    );
  };

  /* ── autocomplete ── */
  let acItems = [];
  let acIndex = -1;

  const hideAutocomplete = () => {
    if (!acBox) return;
    acBox.hidden = true;
    acBox.innerHTML = "";
    acItems = [];
    acIndex = -1;
    input.removeAttribute("aria-activedescendant");
  };

  const showAutocomplete = (items) => {
    if (!acBox || !items.length) { hideAutocomplete(); return; }
    acItems = items;
    acIndex = -1;
    acBox.innerHTML = items
      .map(
        (item, i) => {
          const removeBtn = item.removeQuery
            ? `<button type="button" class="term-autocomplete__remove" data-remove="${item.removeQuery}" aria-label="Remove">&times;</button>`
            : "";
          return `<button type="button" class="term-autocomplete__item" data-ac-idx="${i}" id="term-ac-${i}">
            <span>${item.display}</span>
            ${item.hint ? `<small>${item.hint}</small>` : ""}
            ${removeBtn}
          </button>`;
        }
      )
      .join("");
    acBox.hidden = false;

    acBox.querySelectorAll("[data-ac-idx]").forEach((btn) => {
      btn.addEventListener("mousedown", (e) => {
        if (e.target.closest("[data-remove]")) return;
        e.preventDefault();
        const idx = parseInt(btn.getAttribute("data-ac-idx"), 10);
        const item = acItems[idx];
        if (!item) return;
        input.value = item.command;
        hideAutocomplete();
        executeCommand(item.command);
      });
    });

    acBox.querySelectorAll("[data-remove]").forEach((btn) => {
      btn.addEventListener("mousedown", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const q = btn.getAttribute("data-remove");
        removeHistory(q);
        updateAutocomplete();
      });
    });
  };

  const highlightAutocomplete = () => {
    if (!acBox) return;
    acBox.querySelectorAll(".term-autocomplete__item").forEach((el, i) => {
      el.classList.toggle("is-active", i === acIndex);
    });
    if (acIndex >= 0 && acItems[acIndex]) {
      input.setAttribute("aria-activedescendant", `term-ac-${acIndex}`);
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  };

  const updateAutocomplete = async () => {
    const raw = input.value;
    const trimmed = raw.trim();
    if (!trimmed) { hideAutocomplete(); return; }

    const suggestions = [];
    const lower = trimmed.toLowerCase();
    const isSlash = trimmed.startsWith("/");

    if (isSlash) {
      const afterSlash = trimmed.slice(1).trim();
      if (!afterSlash) {
        suggestions.push({
          display: SEARCH_HINT,
          command: "/",
          hint: "",
        });
      } else {
        const pages = await fetchPageIndex();
        pages
          .filter(
            (p) =>
              p.title.toLowerCase().includes(afterSlash.toLowerCase()) ||
              p.description.toLowerCase().includes(afterSlash.toLowerCase())
          )
          .slice(0, 5)
          .forEach((p) => {
            suggestions.push({
              display: p.title,
              command: p.title,
              hint: "write-up",
            });
          });
      }
    } else {
      endpoints.forEach((ep) => {
        const labelLower = ep.label.toLowerCase();
        const routeClean = ep.route.replace(/^\/|\/$/g, "").toLowerCase();
        if (labelLower.includes(lower) || routeClean.includes(lower)) {
          suggestions.push({
            display: `cd ${ep.label}`,
            command: `cd ${ep.label}`,
            hint: ep.route,
          });
        }
      });

      if ("?".includes(lower) || "help".includes(lower)) {
        suggestions.push({ display: "?", command: "?", hint: "show help" });
      }

      const history = loadHistory();
      history.forEach((h) => {
        if (h.toLowerCase().includes(lower) && h !== trimmed) {
          suggestions.push({
            display: h,
            command: h,
            hint: "recent",
            removeQuery: h,
          });
        }
      });

      if (lower.length >= 2) {
        const pages = await fetchPageIndex();
        pages
          .filter(
            (p) =>
              p.title.toLowerCase().includes(lower) ||
              p.description.toLowerCase().includes(lower)
          )
          .slice(0, 4)
          .forEach((p) => {
            suggestions.push({
              display: p.title,
              command: p.title,
              hint: "write-up",
            });
          });
      }
    }

    if (suggestions.length) showAutocomplete(suggestions);
    else hideAutocomplete();
  };

  /* ── command parsing ── */
  const parseCommand = (raw) => {
    const trimmed = raw.trim();
    if (!trimmed) return null;

    if (trimmed === "?") return { type: "help" };
    if (trimmed === "/") return { type: "search" };

    const cdMatch = trimmed.match(/^cd\s+(.*)/i);
    if (cdMatch) {
      const arg = cdMatch[1].trim().toLowerCase();
      if (arg === "") return { type: "navigate", route: "/" };
      const match = endpoints.find((ep) => {
        const routeClean = ep.route.replace(/^\/|\/$/g, "").toLowerCase();
        const labelClean = ep.label.toLowerCase();
        return routeClean === arg || labelClean === arg;
      });
      if (match) return { type: "navigate", route: match.route };
      return { type: "error", text: `unknown section: ${cdMatch[1].trim()}` };
    }

    return { type: "search-keyword", query: trimmed };
  };

  /* ── feedback ── */
  const setFeedback = (html, className) => {
    feedback.innerHTML = html;
    feedback.className = "term-dropdown__feedback";
    if (className) feedback.classList.add(className);
  };

  /* ── search modal trigger ── */
  const triggerSearch = () => {
    closeDropdown(false);
    window.setTimeout(() => {
      const btn =
        document.getElementById("search-button-mobile") ||
        document.getElementById("search-button");
      btn?.click();
    }, 300);
  };

  /* ── command execution ── */
  const executeCommand = async (raw) => {
    hideAutocomplete();
    const cmd = parseCommand(raw);
    if (!cmd) {
      feedback.textContent = "";
      feedback.className = "term-dropdown__feedback";
      return;
    }

    if (cmd.type === "help") {
      setFeedback(HELP_TEXT.replace(/\n/g, "<br>").replace(/  /g, "&nbsp;&nbsp;"), "");
      return;
    }

    if (cmd.type === "search") {
      triggerSearch();
      return;
    }

    if (cmd.type === "navigate") {
      setFeedback(`\u2192 redirecting to ${cmd.route} ...`, "ok");
      window.setTimeout(() => {
        closeDropdown(false);
        window.location.href = cmd.route;
      }, 350);
      return;
    }

    if (cmd.type === "error") {
      setFeedback(cmd.text, "term-dropdown__feedback--err");
      return;
    }

    if (cmd.type === "search-keyword") {
      saveHistory(cmd.query);
      setFeedback("searching...", "");
      const pages = await fetchPageIndex();
      const results = searchPages(cmd.query);
      if (results.length === 0) {
        setFeedback(`no results for "${cmd.query}"`, "term-dropdown__feedback--err");
        return;
      }
      const list = results
        .slice(0, 5)
        .map(
          (p) =>
            `<a class="term-dropdown__result" href="${p.permalink}">${p.title}</a>`
        )
        .join("");
      const more =
        results.length > 5
          ? `<span class="term-dropdown__result-more">+${results.length - 5} more</span>`
          : "";
      setFeedback(
        `${results.length} result${results.length > 1 ? "s" : ""} for "${cmd.query}":<br>${list}${more}`,
        ""
      );
      return;
    }
  };

  /* ── dropdown open / close ── */
  let returnFocus = null;
  let isOpen = false;

  const positionBelowHeader = () => {
    const header = document.querySelector(".fixed.inset-x-0");
    if (header) {
      const rect = header.getBoundingClientRect();
      menu.style.top = `${rect.bottom}px`;
    }
  };

  const openDropdown = (trigger) => {
    returnFocus = trigger;
    positionBelowHeader();
    isOpen = true;
    document.body.style.overflow = "hidden";
    menu.classList.add("is-open");
    menu.setAttribute("aria-hidden", "false");
    openButtons.forEach((b) => b.setAttribute("aria-expanded", "true"));
    window.setTimeout(() => input.focus(), 100);
  };

  const closeDropdown = (restoreFocus = true) => {
    isOpen = false;
    document.body.style.overflow = "";
    menu.classList.remove("is-open");
    menu.setAttribute("aria-hidden", "true");
    openButtons.forEach((b) => b.setAttribute("aria-expanded", "false"));
    input.value = "";
    feedback.textContent = "";
    feedback.className = "term-dropdown__feedback";
    hideAutocomplete();
    if (restoreFocus) returnFocus?.focus();
  };

  /* ── event listeners ── */
  openButtons.forEach((btn) =>
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (isOpen) closeDropdown();
      else openDropdown(btn);
    })
  );

  input.addEventListener("input", () => {
    updateAutocomplete();
  });

  input.addEventListener("keydown", (e) => {
    if (acBox && !acBox.hidden && acItems.length) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        acIndex = (acIndex + 1) % acItems.length;
        highlightAutocomplete();
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        acIndex = (acIndex - 1 + acItems.length) % acItems.length;
        highlightAutocomplete();
        return;
      }
      if (e.key === "Tab" && acIndex >= 0) {
        e.preventDefault();
        const item = acItems[acIndex];
        if (item) {
          input.value = item.command;
          hideAutocomplete();
          executeCommand(item.command);
        }
        return;
      }
    }

    if (e.key === "Enter") {
      e.preventDefault();
      if (acIndex >= 0 && acItems[acIndex]) {
        const item = acItems[acIndex];
        input.value = item.command;
        hideAutocomplete();
        executeCommand(item.command);
      } else {
        executeCommand(input.value);
      }
    } else if (e.key === "Escape") {
      if (acBox && !acBox.hidden) {
        hideAutocomplete();
      } else {
        closeDropdown();
      }
    }
  });

  input.addEventListener("blur", () => {
    window.setTimeout(hideAutocomplete, 150);
  });

  endpointButtons.forEach((btn, i) =>
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const ep = endpoints[i];
      if (!ep) return;
      input.value = `cd ${ep.label}`;
      executeCommand(input.value);
    })
  );

  menu.addEventListener("keydown", (e) => {
    if (e.key !== "Tab") return;
    const focusable = [input, ...endpointButtons];
    const first = focusable[0];
    const last = focusable.at(-1);
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  });

  document.addEventListener("click", (e) => {
    if (!isOpen) return;
    if (menu.contains(e.target)) return;
    if (openButtons.some((b) => b.contains(e.target))) return;
    closeDropdown();
  });

  window.addEventListener("resize", () => {
    if (isOpen) positionBelowHeader();
  });

  /* ── utc clock ── */
  const updateUtc = () => {
    if (!utcStatus) return;
    const time = new Intl.DateTimeFormat("en-GB", {
      timeZone: "UTC",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(new Date());
    utcStatus.textContent = `${time} UTC // SYSTEM ONLINE`;
  };

  updateUtc();
  window.setInterval(updateUtc, 1000);
});
