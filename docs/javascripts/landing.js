// The landing page's extension cards (#6). The page is written with a card per extension so it reads without
// JavaScript; this replaces them with one card per entry in extensions.json, each showing the version its docs call
// `latest` (from mike's versions.json under the extension's prefix), or "not released yet" before its first final.
(function () {
  var cards = document.getElementById("aesir-extensions");
  if (!cards || !window.fetch) return;
  var root = new URL("./", location.href);

  function text(tag, className, value) {
    var el = document.createElement(tag);
    if (className) el.className = className;
    el.textContent = value;
    return el;
  }

  function link(href, label) {
    var a = document.createElement("a");
    a.href = href;
    a.textContent = label;
    return a;
  }

  function latest(path) {
    return fetch(new URL(path + "/versions.json", root)).then(function (response) {
      return response.ok ? response.json() : [];
    }).then(function (versions) {
      var entry = versions.filter(function (v) { return (v.aliases || []).indexOf("latest") !== -1; })[0];
      return entry ? entry.version : null;
    }).catch(function () { return null; });
  }

  fetch(new URL("extensions.json", root)).then(function (response) {
    if (!response.ok) throw new Error(response.status);
    return response.json();
  }).then(function (list) {
    return Promise.all(list.map(function (entry) {
      return latest(entry.path).then(function (version) { return [entry, version]; });
    }));
  }).then(function (rows) {
    var fragment = document.createDocumentFragment();
    rows.forEach(function (row) {
      var entry = row[0], version = row[1];
      var card = document.createElement("div");
      card.className = "aesir-card";
      card.appendChild(text("h3", "", entry.name));
      card.appendChild(text("span", "aesir-badge", version ? version : "not released yet"));
      card.appendChild(text("p", "aesir-question", entry.question));
      card.appendChild(text("p", "", entry.summary));
      var install = document.createElement("p");
      install.appendChild(text("code", "", entry.install));
      card.appendChild(install);
      var links = document.createElement("div");
      links.className = "aesir-links";
      links.appendChild(link(new URL(entry.path + "/", root).href, "Documentation"));
      if (entry.action) links.appendChild(link(entry.action, "GitHub Action"));
      card.appendChild(links);
      fragment.appendChild(card);
    });
    cards.replaceChildren(fragment);
  }).catch(function () {});
})();
