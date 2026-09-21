/* Drupal Knowledge search.
 *
 * A direct mirror of the ranking the released query layer performs, with the
 * band values taken from the generated index rather than written here, so the
 * browser cannot invent an ordering the command line would not produce.
 *
 * Nothing is sent anywhere. The index is fetched once and matched locally.
 */
(function () {
  "use strict";

  var TOKEN_RE = /[A-Za-z0-9_./:-]+/g;

  var input = document.getElementById("q");
  var status = document.getElementById("search-status");
  var list = document.getElementById("search-results");
  var form = document.querySelector("form.search");
  if (!input || !status || !list || !form) return;

  var index = null;

  function fields(row) {
    return {
      identity: row.identity || [],
      structured: row.structured || [],
      title: [row.title],
      body: [row.summary].concat(row.body || [])
    };
  }

  /* The same six comparisons, in the same order, as score_record. */
  function score(term, groups, bands) {
    var lowered = term.trim().toLowerCase();
    var i, value, tokens;

    for (i = 0; i < groups.identity.length; i++) {
      if (groups.identity[i] && groups.identity[i].toLowerCase() === lowered) {
        return [bands.exact_id, "exact identifier match"];
      }
    }
    for (i = 0; i < groups.structured.length; i++) {
      if (groups.structured[i] && groups.structured[i].toLowerCase() === lowered) {
        return [bands.exact_field, "exact structured field match"];
      }
    }
    for (i = 0; i < groups.identity.length; i++) {
      value = groups.identity[i];
      if (value && lowered.length >= 3 && value.toLowerCase().indexOf(lowered) === 0) {
        return [bands.prefix_id, "identifier prefix match"];
      }
    }
    var order = ["title", "structured"];
    for (var g = 0; g < order.length; g++) {
      var group = groups[order[g]];
      for (i = 0; i < group.length; i++) {
        if (!group[i]) continue;
        tokens = String(group[i]).match(TOKEN_RE) || [];
        for (var t = 0; t < tokens.length; t++) {
          if (tokens[t].toLowerCase() === lowered) {
            return [bands.exact_token, "exact word in " + order[g]];
          }
        }
      }
    }
    for (i = 0; i < groups.title.length; i++) {
      if (groups.title[i] && groups.title[i].toLowerCase().indexOf(lowered) !== -1) {
        return [bands.title_substring, "title contains the term"];
      }
    }
    for (i = 0; i < groups.body.length; i++) {
      if (groups.body[i] && groups.body[i].toLowerCase().indexOf(lowered) !== -1) {
        return [bands.body_substring, "text contains the term"];
      }
    }
    return [0, ""];
  }

  function badgeText(trustClass) {
    var labels = {
      reviewed_drupal_knowledge: "Reviewed Drupal Knowledge",
      source_derived_authoritative: "Authoritative Drupal Source Record",
      reviewed_implementation_rule: "Reviewed Implementation Rule",
      proven_case_context_only: "Internal Proven Solved Case",
      untrusted_discovery_signal: "Untrusted Discovery Signal"
    };
    return labels[trustClass] || trustClass;
  }

  function render(term, matches) {
    list.textContent = "";
    if (!term) {
      status.textContent = "Searching " + index.rows.length + " published records.";
      return;
    }
    if (!matches.length) {
      status.textContent =
        "No record matches “" + term + "”. Drupal Knowledge holds a bounded " +
        "record set, so no match is not evidence that the subject is unproblematic.";
      return;
    }
    status.textContent =
      matches.length + " record(s) match “" + term + "”, ranked by how exactly they match.";
    matches.forEach(function (match) {
      var row = match.row;
      var li = document.createElement("li");
      var link = document.createElement("a");
      link.href = row.route;
      link.textContent = row.title;
      li.appendChild(link);

      var summary = document.createElement("span");
      summary.className = "row-summary";
      summary.textContent = row.summary || row.id;
      li.appendChild(summary);

      var trust = document.createElement("span");
      trust.className = "result-trust";
      var badge = document.createElement("span");
      badge.className = "badge badge--" + row.trust_class;
      badge.textContent = badgeText(row.trust_class);
      trust.appendChild(badge);
      trust.appendChild(document.createTextNode(" " + match.reason));
      li.appendChild(trust);

      list.appendChild(li);
    });
  }

  function run(term) {
    if (!index) return;
    var matches = [];
    index.rows.forEach(function (row) {
      var result = score(term, fields(row), index.ranking);
      if (result[0]) matches.push({ rank: result[0], row: row, reason: result[1] });
    });
    /* Rank descending, then canonical id ascending: the same total order the
       command line uses, so a tie never depends on load order. */
    matches.sort(function (a, b) {
      if (a.rank !== b.rank) return b.rank - a.rank;
      return a.row.id < b.row.id ? -1 : a.row.id > b.row.id ? 1 : 0;
    });
    render(term, matches.slice(0, 50));
  }

  function currentTerm() {
    var params = new URLSearchParams(window.location.search);
    return (params.get("q") || "").trim();
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var term = input.value.trim();
    var url = term ? "/search/?q=" + encodeURIComponent(term) : "/search/";
    window.history.replaceState({}, "", url);
    run(term);
  });

  status.textContent = "Loading the search index…";
  fetch("/search-index.json")
    .then(function (response) {
      if (!response.ok) throw new Error("index unavailable");
      return response.json();
    })
    .then(function (payload) {
      index = payload;
      var term = currentTerm();
      input.value = term;
      run(term);
    })
    .catch(function () {
      status.textContent =
        "The search index could not be loaded. Every domain is still browsable " +
        "from the navigation above.";
    });
})();
