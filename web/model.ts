/** Jason Stys: runtime-checked bounded evidence contracts, filtering and truthful observed-versus-expected summaries. */
/* BEGIN CODE MAP (generated; npm run code-map)
 * definition: Case — line 34
 * field: id — line 35
 * field: title — line 36
 * field: principal — line 37
 * field: action — line 38
 * field: resource — line 39
 * field: expected — line 40
 * field: observed — line 41
 * field: reason — line 42
 * field: elapsed_ms — line 43
 * definition: Report — line 45
 * field: schema — line 46
 * field: synthetic — line 47
 * field: source — line 48
 * field: cases — line 49
 * definition: shape — line 53
 * parameter: value — line 54
 * parameter: keys — line 55
 * definition: decode — line 65
 * parameter: value — line 65
 * variable: ids — line 77
 * variable: row — line 78
 * variable: field — line 93
 * variable: text — line 101
 * definition: filter — line 135
 * parameter: rows — line 135
 * parameter: query — line 135
 * parameter: verdict — line 135
 * variable: needle — line 141
 * parameter: row — line 143
END CODE MAP */
export interface Case {
  id: string;
  title: string;
  principal: string;
  action: string;
  resource: string;
  expected: boolean;
  observed: boolean;
  reason: string;
  elapsed_ms: number;
}
export interface Report {
  schema: 1;
  synthetic: true;
  source: string;
  cases: Case[];
}

/** Require the exact known object shape; reject null, arrays and extra private-bearing fields. */
function shape(
  value: unknown,
  keys: string[],
): value is Record<string, unknown> {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === keys.sort().join(",")
  );
}
/** Validate server data before rendering; no coercion of strings into booleans or arbitrary HTML. */
export function decode(value: unknown): Report {
  if (
    !shape(value, ["schema", "synthetic", "source", "cases"]) ||
    value.schema !== 1 ||
    value.synthetic !== true ||
    typeof value.source !== "string" ||
    !/^(?:[a-f0-9]{40}|uncommitted)$/.test(value.source) ||
    !Array.isArray(value.cases) ||
    value.cases.length < 1 ||
    value.cases.length > 128
  )
    throw new Error("evidence_rejected");
  const ids = new Set<string>();
  for (const row of value.cases) {
    if (
      !shape(row, [
        "id",
        "title",
        "principal",
        "action",
        "resource",
        "expected",
        "observed",
        "reason",
        "elapsed_ms",
      ])
    )
      throw new Error("evidence_rejected");
    for (const field of [
      "id",
      "title",
      "principal",
      "action",
      "resource",
      "reason",
    ]) {
      const text = row[field];
      if (
        typeof text !== "string" ||
        !text.length ||
        text.length > 200 ||
        /[\u0000-\u001f]/u.test(text)
      )
        throw new Error("evidence_rejected");
    }
    if (
      typeof row.id !== "string" ||
      !/^[A-Z][A-Z0-9-]{1,63}$/.test(row.id) ||
      ids.has(row.id) ||
      !["read", "publish", "delete", "rotate"].includes(row.action as string) ||
      !["alpha-docs", "alpha-artifacts", "beta-docs", "alpha-keys"].includes(
        row.resource as string,
      ) ||
      !["allowed", "policy_denied", "credential_rejected"].includes(
        row.reason as string,
      ) ||
      typeof row.expected !== "boolean" ||
      typeof row.observed !== "boolean" ||
      (row.reason === "allowed") !== row.observed ||
      typeof row.elapsed_ms !== "number" ||
      !Number.isFinite(row.elapsed_ms) ||
      row.elapsed_ms < 0 ||
      row.elapsed_ms > 60000
    )
      throw new Error("evidence_rejected");
    ids.add(row.id);
  }
  return value as unknown as Report;
}
/** Filter only displayed evidence, never grant access; a legitimate denied request can be a passing test. */
export function filter(rows: Case[], query: string, verdict: string): Case[] {
  if (
    query.length > 200 ||
    !["all", "allow", "deny", "failed"].includes(verdict)
  )
    throw new Error("filter_rejected");
  const needle = query.toLowerCase();
  return rows.filter(
    (row) =>
      [row.id, row.title, row.principal, row.resource, row.action]
        .join(" ")
        .toLowerCase()
        .includes(needle) &&
      (verdict === "all" ||
        (verdict === "allow" && row.observed) ||
        (verdict === "deny" && !row.observed) ||
        (verdict === "failed" && row.expected !== row.observed)),
  );
}
