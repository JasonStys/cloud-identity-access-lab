/** Jason Stys: accessible immutable evidence viewer; no token entry, account data, remote APIs or cloud mutation. */
/* BEGIN CODE MAP (generated; npm run code-map)
 * definition: control — line 29
 * parameter: id — line 30
 * parameter: type — line 31
 * parameter: args — line 31
 * variable: node — line 33
 * variable: search — line 37
 * variable: verdict — line 38
 * variable: body — line 39
 * variable: status — line 40
 * variable: summary — line 41
 * variable: report — line 42
 * definition: refresh — line 45
 * variable: rows — line 47
 * variable: row — line 49
 * variable: tr — line 50
 * variable: text — line 51
 * variable: td — line 61
 * definition: load — line 72
 * variable: response — line 74
 * variable: raw — line 80
 * variable: passed — line 84
 * parameter: row — line 85
END CODE MAP */
import { decode, filter, type Report } from "./model.js";

/** Require an authored semantic control before installing handlers; fail clearly on broken page contracts. */
function control<T extends HTMLElement>(
  id: string,
  type: new (...args: never[]) => T,
): T {
  const node = document.getElementById(id);
  if (!(node instanceof type)) throw new Error("control_missing");
  return node;
}
const search = control("search", HTMLInputElement);
const verdict = control("verdict", HTMLSelectElement);
const body = control("rows", HTMLTableSectionElement);
const status = control("status", HTMLParagraphElement);
const summary = control("summary", HTMLParagraphElement);
let report: Report | undefined;

/** Render known fields exclusively with text nodes, preserving error visibility and keyboard controls. */
function refresh(): void {
  if (!report) return;
  const rows = filter(report.cases, search.value, verdict.value);
  body.replaceChildren();
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const text of [
      row.id,
      row.title,
      row.principal,
      row.action + " · " + row.resource,
      row.expected ? "Allow" : "Deny",
      row.observed ? "Allow" : "Deny",
      row.expected === row.observed ? "Pass" : "FAIL",
      row.reason,
    ]) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.append(td);
    }
    body.append(tr);
  }
  status.textContent =
    rows.length +
    " scenarios shown. Denied access can be a passing security test.";
}
/** Read one fixed same-origin bounded response; no dynamic target URL, credentials or token transport. */
async function load(): Promise<void> {
  try {
    const response = await fetch("/evidence.json", {
      credentials: "omit",
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error("evidence_unavailable");
    const raw = await response.text();
    if (new TextEncoder().encode(raw).length > 131072)
      throw new Error("evidence_rejected");
    report = decode(JSON.parse(raw));
    const passed = report.cases.filter(
      (row) => row.expected === row.observed,
    ).length;
    summary.textContent =
      passed +
      "/" +
      report.cases.length +
      " actual signed-identity/OPA scenarios passed · Source: " +
      report.source;
    refresh();
  } catch {
    status.textContent =
      "Evidence could not be validated. Restart the local lab after checking tool and build prerequisites.";
  }
}
search.addEventListener("input", refresh);
verdict.addEventListener("change", refresh);
void load();
