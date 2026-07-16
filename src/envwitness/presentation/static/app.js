"use strict";

const state = {
  capsules: [],
};

const elements = {
  health: document.querySelector("#health"),
  capsuleCount: document.querySelector("#capsule-count"),
  factCount: document.querySelector("#fact-count"),
  redactedCount: document.querySelector("#redacted-count"),
  capsuleList: document.querySelector("#capsule-list"),
  baseline: document.querySelector("#baseline"),
  candidate: document.querySelector("#candidate"),
  compare: document.querySelector("#compare"),
  refresh: document.querySelector("#refresh"),
  emptyState: document.querySelector("#empty-state"),
  results: document.querySelector("#results"),
  hints: document.querySelector("#hints"),
  differences: document.querySelector("#differences"),
};

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(payload.detail || response.statusText);
  }
  return response.json();
}

function text(value) {
  if (value === null || value === undefined) {
    return "-";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

function createElement(tagName, className, content) {
  const element = document.createElement(tagName);
  if (className) {
    element.className = className;
  }
  if (content !== undefined) {
    element.textContent = content;
  }
  return element;
}

function renderCapsules() {
  elements.capsuleList.replaceChildren();
  const factCount = state.capsules.reduce((sum, capsule) => sum + capsule.fact_count, 0);
  const redactedCount = state.capsules.reduce(
    (sum, capsule) => sum + capsule.redacted_fact_count,
    0,
  );
  elements.capsuleCount.textContent = String(state.capsules.length);
  elements.factCount.textContent = String(factCount);
  elements.redactedCount.textContent = String(redactedCount);

  if (state.capsules.length === 0) {
    const empty = createElement("div", "capsule-row");
    empty.append(createElement("strong", "", "No capsules yet"));
    empty.append(createElement("span", "", "Run envwitness capture to create one."));
    elements.capsuleList.append(empty);
  } else {
    state.capsules.forEach((capsule) => {
      const row = createElement("div", "capsule-row");
      row.append(createElement("strong", "", capsule.name));
      row.append(
        createElement(
          "span",
          "",
          `${capsule.fact_count} facts | ${new Date(capsule.created_at).toLocaleString()}`,
        ),
      );
      elements.capsuleList.append(row);
    });
  }
  renderSelectors();
}

function renderSelectors() {
  const previousBaseline = elements.baseline.value;
  const previousCandidate = elements.candidate.value;
  elements.baseline.replaceChildren();
  elements.candidate.replaceChildren();
  state.capsules.forEach((capsule) => {
    const baselineOption = new Option(capsule.name, capsule.name);
    const candidateOption = new Option(capsule.name, capsule.name);
    elements.baseline.add(baselineOption);
    elements.candidate.add(candidateOption);
  });
  if (state.capsules.length > 0) {
    const workingCapsule = state.capsules.find((capsule) =>
      capsule.name.toLowerCase().includes("working"),
    );
    const failingCapsule = state.capsules.find((capsule) =>
      capsule.name.toLowerCase().includes("failing"),
    );
    elements.baseline.value = previousBaseline || workingCapsule?.name || state.capsules[0].name;
    elements.candidate.value =
      previousCandidate ||
      failingCapsule?.name ||
      state.capsules[Math.min(1, state.capsules.length - 1)].name;
  }
}

async function loadCapsules() {
  try {
    const payload = await fetchJson("/api/v1/capsules");
    state.capsules = payload.capsules;
    elements.health.classList.add("online");
    elements.health.lastChild.textContent = " Local API online";
    renderCapsules();
  } catch (error) {
    elements.health.classList.remove("online");
    elements.health.lastChild.textContent = ` ${error.message}`;
  }
}

function renderComparison(report) {
  elements.hints.replaceChildren();
  elements.differences.replaceChildren();
  report.hints.forEach((hint) => {
    const item = createElement("article", "hint");
    item.append(createElement("strong", "", hint.title));
    item.append(createElement("p", "", hint.explanation));
    elements.hints.append(item);
  });
  if (report.hints.length === 0) {
    const item = createElement("article", "hint");
    item.append(createElement("strong", "", "No semantic drift"));
    item.append(createElement("p", "", "The stored evidence is identical."));
    elements.hints.append(item);
  }
  report.differences.forEach((difference) => {
    const row = document.createElement("tr");
    row.append(
      createElement("td", `severity ${difference.severity}`, difference.severity),
      createElement("td", "", difference.key),
      createElement("td", "", difference.kind),
      createElement("td", "", text(difference.baseline_value)),
      createElement("td", "", text(difference.candidate_value)),
    );
    elements.differences.append(row);
  });
  elements.emptyState.hidden = true;
  elements.results.hidden = false;
}

async function compareCapsules() {
  if (!elements.baseline.value || !elements.candidate.value) {
    return;
  }
  elements.compare.disabled = true;
  elements.compare.textContent = "Comparing";
  try {
    const report = await fetchJson("/api/v1/compare", {
      method: "POST",
      body: JSON.stringify({
        baseline: elements.baseline.value,
        candidate: elements.candidate.value,
      }),
    });
    renderComparison(report);
  } catch (error) {
    elements.emptyState.hidden = false;
    elements.results.hidden = true;
    elements.emptyState.querySelector("strong").textContent = "Comparison failed";
    elements.emptyState.querySelector("span").textContent = error.message;
  } finally {
    elements.compare.disabled = false;
    elements.compare.textContent = "Compare";
  }
}

elements.refresh.addEventListener("click", loadCapsules);
elements.compare.addEventListener("click", compareCapsules);
loadCapsules();
