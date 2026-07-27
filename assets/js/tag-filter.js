document.addEventListener("DOMContentLoaded", () => {
  const browser = document.querySelector("[data-tag-browser]");
  if (!browser) return;

  const buttons = [...browser.querySelectorAll("[data-tag-filter]")];
  const items = [...browser.querySelectorAll("[data-tag-item]")];
  const count = browser.querySelector("[data-visible-count]");
  const empty = browser.querySelector("[data-filter-empty]");

  function updateCounts() {
    const tagCounts = {};
    items.forEach((item) => {
      const tags = item.dataset.tags.trim().split(/\s+/).filter(Boolean);
      tags.forEach((t) => {
        tagCounts[t] = (tagCounts[t] || 0) + 1;
      });
    });
    buttons.forEach((btn) => {
      const tag = btn.dataset.tagFilter;
      const small = btn.querySelector("small");
      if (!small) return;
      if (tag === "all") {
        small.textContent = String(items.length);
      } else {
        small.textContent = String(tagCounts[tag] || 0);
      }
    });
  }

  updateCounts();

  const applyFilter = (requestedTag, updateUrl = true) => {
    const tag = buttons.some((button) => button.dataset.tagFilter === requestedTag)
      ? requestedTag
      : "all";
    let visible = 0;

    buttons.forEach((button) => {
      const active = button.dataset.tagFilter === tag;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });

    items.forEach((item) => {
      const tags = item.dataset.tags.trim().split(/\s+/);
      const show = tag === "all" || tags.includes(tag);
      item.hidden = !show;
      if (show) visible += 1;
    });

    if (count) count.textContent = String(visible);
    if (empty) empty.hidden = visible !== 0;

    if (updateUrl) {
      const url = new URL(window.location.href);
      if (tag === "all") url.searchParams.delete("tag");
      else url.searchParams.set("tag", tag);
      window.history.replaceState({}, "", url);
    }
  };

  buttons.forEach((button) => {
    button.addEventListener("click", () => applyFilter(button.dataset.tagFilter));
  });

  applyFilter(new URLSearchParams(window.location.search).get("tag") || "all", false);
});
