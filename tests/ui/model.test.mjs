/** Jason Stys: native compiled-TypeScript evidence/negative/filter contracts, not policy-engine simulation. */
/* BEGIN CODE MAP (generated; npm run code-map)
 * definition: fixture — line 15
 * variable: report — line 58
 * variable: invalid — line 67
 * variable: [field, value] — line 82
 * variable: report — line 98
 * variable: report — line 104
END CODE MAP */
import { test } from "node:test";
import assert from "node:assert/strict";
import { decode, filter } from "../../dist/model.js";

/** Build a small shape fixture for viewer tests, never a claimed native authorization result. */
function fixture() {
  return {
    schema: 1,
    synthetic: true,
    source: "uncommitted",
    cases: [
      {
        id: "TEST-ALLOW",
        title: "Synthetic allow",
        principal: "engineer-alpha",
        action: "read",
        resource: "alpha-docs",
        expected: true,
        observed: true,
        reason: "allowed",
        elapsed_ms: 1,
      },
      {
        id: "TEST-DENY",
        title: "Synthetic deny",
        principal: "reader-beta",
        action: "read",
        resource: "alpha-docs",
        expected: false,
        observed: false,
        reason: "policy_denied",
        elapsed_ms: 2,
      },
      {
        id: "TEST-FAIL",
        title: "Contradictory access",
        principal: "engineer-alpha",
        action: "read",
        resource: "alpha-docs",
        expected: false,
        observed: true,
        reason: "allowed",
        elapsed_ms: 3,
      },
    ],
  };
}
test("Validate genuine-shaped evidence and preserve denied-versus-passing distinction", () => {
  const report = decode(fixture());
  assert.equal(filter(report.cases, "", "deny").length, 1);
  assert.equal(filter(report.cases, "", "failed")[0].id, "TEST-FAIL");
  assert.equal(filter(report.cases, "READER", "all").length, 1);
  assert.equal(filter(report.cases, "", "allow").length, 2);
  assert.equal(filter(report.cases, "not-present", "all").length, 0);
  assert.throws(() => filter(report.cases, "x".repeat(201), "all"));
  assert.throws(() => filter(report.cases, "", "unknown"));
});
for (const invalid of [
  null,
  [],
  {},
  { ...fixture(), synthetic: false },
  { ...fixture(), schema: "1" },
  { ...fixture(), source: "not-source" },
  { ...fixture(), cases: [] },
  { ...fixture(), cases: fixture().cases.concat(fixture().cases) },
]) {
  test(
    "Reject invalid report shape " + JSON.stringify(invalid).slice(0, 40),
    () => assert.throws(() => decode(invalid)),
  );
}
for (const [field, value] of [
  ["expected", "true"],
  ["observed", 1],
  ["reason", "private"],
  ["reason", "policy_denied"],
  ["elapsed_ms", Infinity],
  ["elapsed_ms", true],
  ["elapsed_ms", -1],
  ["id", "bad"],
  ["title", ""],
  ["title", "x\n"],
  ["action", "*"],
  ["resource", "*"],
  ["token", "private"],
]) {
  test("Reject invalid row " + field + " " + String(value).slice(0, 20), () => {
    const report = fixture();
    report.cases[0][field] = value;
    assert.throws(() => decode(report));
  });
}
test("Hostile-looking titles remain inert strings, not HTML or executable code", () => {
  const report = fixture();
  report.cases[0].title = '<img src=x onerror="alert(1)">';
  assert.equal(decode(report).cases[0].title, report.cases[0].title);
});
