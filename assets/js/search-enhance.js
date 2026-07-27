document.addEventListener("DOMContentLoaded", function () {
  var searchInput = document.getElementById("search-query");
  var searchResults = document.getElementById("search-results");
  var searchWrapper = document.getElementById("search-wrapper");
  if (!searchInput || !searchResults || !searchWrapper) return;

  var STORAGE_KEY = "blowfish_search_history";
  var noResultEl = document.createElement("div");
  noResultEl.id = "search-no-results";
  noResultEl.style.cssText = "padding:6px 10px;color:#94a3b8;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;display:none;";
  noResultEl.innerHTML = '<span style="color:#f87171;margin-right:4px;">&gt;</span> 404 &mdash; not found';

  var historyEl = document.createElement("div");
  historyEl.id = "search-history";
  historyEl.style.cssText = "padding:0 10px;display:none;";
  historyEl.innerHTML = '<div style="padding:4px 0;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;">Recent searches</div><ul id="search-history-list" style="list-style:none;margin:0;padding:0;"></ul>';

  var section = searchResults.parentNode;
  section.insertBefore(noResultEl, searchResults);
  section.insertBefore(historyEl, searchResults);

  var historyList = document.getElementById("search-history-list");

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
    catch (e) { return []; }
  }

  function saveHistory(term) {
    var q = term.trim();
    if (!q) return;
    var h = loadHistory().filter(function (x) { return x !== q; });
    h.unshift(q);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(h));
  }

  function removeHistory(term) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(loadHistory().filter(function (x) { return x !== term; })));
  }

  function renderHistory() {
    var history = loadHistory();
    if (history.length === 0) {
      historyEl.style.display = "none";
      historyList.innerHTML = "";
      return;
    }
    historyEl.style.display = "block";
    historyList.innerHTML = history.map(function (term) {
      var safe = term.replace(/</g, "&lt;").replace(/"/g, "&quot;");
      return '<li style="display:flex;align-items:center;justify-content:space-between;padding:8px 10px;margin-bottom:3px;border-radius:6px;background:rgba(30,41,59,0.6);color:#cbd5e1;font-size:14px;cursor:pointer;">' +
        '<span class="history-term" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + safe + '</span>' +
        '<button type="button" class="history-remove" data-term="' + safe + '" style="flex-shrink:0;padding:0 6px;margin-left:8px;border:0;background:transparent;color:#64748b;font-size:16px;line-height:1;cursor:pointer;">x</button></li>';
    }).join("");
  }

  function updateVisibility() {
    var hasQuery = searchInput.value.trim().length > 0;
    var hasResults = searchResults.children.length > 0;
    noResultEl.style.display = (hasQuery && !hasResults) ? "block" : "none";
    if (!hasQuery && !hasResults) {
      renderHistory();
    } else {
      historyEl.style.display = "none";
    }
  }

  searchInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      var term = searchInput.value.trim();
      if (term) saveHistory(term);
    }
  });

  searchInput.addEventListener("input", updateVisibility);
  searchInput.addEventListener("focus", updateVisibility);

  searchResults.addEventListener("click", function (e) {
    if (e.target.closest("a")) {
      var term = searchInput.value.trim();
      if (term) saveHistory(term);
    }
  });

  historyList.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-term]");
    if (btn) {
      e.preventDefault();
      e.stopPropagation();
      removeHistory(btn.getAttribute("data-term"));
      renderHistory();
      return;
    }
    var termEl = e.target.closest(".history-term");
    if (termEl) {
      searchInput.value = termEl.textContent;
      searchInput.dispatchEvent(new Event("input"));
      searchInput.dispatchEvent(new Event("keyup"));
    }
  });

  new MutationObserver(updateVisibility).observe(searchResults, { childList: true });
  new MutationObserver(updateVisibility).observe(searchWrapper, { attributes: true, attributeFilter: ["class", "style"] });
});
