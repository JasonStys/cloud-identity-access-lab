/** Jason Stys: actual native-generated evidence browser filters, downloads, literal rendering and accessible scope. */
/* BEGIN CODE MAP (generated; npm run code-map)
 * parameter: { page, } — line 23
 * parameter: { page, } — line 42
 * variable: remote — line 45
 * parameter: request — line 46
 * variable: response — line 52
 * variable: report — line 53
 * variable: pending — line 58
 * parameter: { page, } — line 65
 * variable: dialogs — line 68
 * parameter: dialog — line 69
 * parameter: route — line 73
 * variable: original — line 74
 * variable: report — line 75
 * parameter: route — line 88
 * parameter: { page, } — line 97
 * variable: results — line 117
END CODE MAP */
import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("Show actual matrix and distinguish successful denial from failed regression", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.locator("#summary")).toContainText("31/31");
  await expect(page.locator("#rows tr")).toHaveCount(31);
  await page
    .getByLabel("Observed decision", { exact: true })
    .selectOption("deny");
  await expect(page.locator("#rows tr")).not.toHaveCount(31);
  await page.getByLabel("Search scenarios", { exact: true }).fill("R-REVOKED");
  await expect(page.locator("#rows tr")).toHaveCount(1);
  await expect(page.locator("#rows")).toContainText("Pass");
  await expect(page.locator("#rows")).toContainText("credential_rejected");
  await page
    .getByLabel("Observed decision", { exact: true })
    .selectOption("failed");
  await expect(page.locator("#rows tr")).toHaveCount(0);
});
test("Sanitized downloads and requests never transport tokens or remote telemetry", async ({
  page,
}) => {
  const remote = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:53034/"))
      remote.push(request.url());
  });
  await page.goto("/");
  await expect(page.locator("#summary")).toContainText("31/31");
  const response = await page.request.get("/evidence.json");
  const report = await response.json();
  expect(report.synthetic).toBe(true);
  expect(report.cases).toHaveLength(31);
  expect(JSON.stringify(report)).not.toContain("eyJ");
  expect(response.headers()["content-disposition"]).toContain("attachment");
  const pending = page.waitForEvent("download");
  await page
    .getByRole("link", { name: "Download sanitized JSON", exact: true })
    .click();
  expect((await pending).suggestedFilename()).toBe("evidence.json");
  expect(remote).toEqual([]);
});
test("Validate before rendering, keep hostile-looking labels literal and fail safely on malformed evidence", async ({
  page,
}) => {
  let dialogs = 0;
  page.on("dialog", (dialog) => {
    dialogs++;
    void dialog.dismiss();
  });
  await page.route("**/evidence.json", async (route) => {
    const original = await route.fetch();
    const report = await original.json();
    report.cases[0].title = '<img src=x onerror="alert(1)">';
    await route.fulfill({ json: report });
  });
  await page.goto("/");
  await expect(page.locator("#rows")).toContainText(
    '<img src=x onerror="alert(1)">',
  );
  expect(
    await page.locator("#rows img, #rows script, #rows iframe").count(),
  ).toBe(0);
  expect(dialogs).toBe(0);
  await page.unroute("**/evidence.json");
  await page.route("**/evidence.json", (route) =>
    route.fulfill({ json: { private: "untrusted" } }),
  );
  await page.reload();
  await expect(page.getByRole("status")).toContainText(
    "could not be validated",
  );
  await expect(page.locator("#rows tr")).toHaveCount(0);
});
test("Keyboard, mobile containment, axe accessibility and honest help", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.locator("#summary")).toContainText("31/31");
  await page.getByLabel("Search scenarios", { exact: true }).focus();
  await page.keyboard.type("W-FORK");
  await expect(page.locator("#rows tr")).toHaveCount(1);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page
    .getByText("Help, scope and real-provider integration", { exact: true })
    .click();
  await expect(page.locator("details")).toContainText(
    "No AWS IAM Simulator or deployment",
  );
  await expect(page.locator("footer")).toContainText("Jason Stys");
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});
