import { expect, type Page, test } from "@playwright/test";

import { waitForAnimations } from "../helpers/animations";
import { installMockBridge } from "../helpers/bridge";

const PAGES_INFO = {
  pages: { host_prefix: "apps.", login_path: "/_buzz/login" },
  supported_extensions: ["buzz-pages"],
};

async function routeRelayInfo(page: Page, info: object) {
  await page.route("http://localhost:3000/info", (route) =>
    route.fulfill({
      body: JSON.stringify(info),
      contentType: "application/nostr+json",
    }),
  );
}

async function openBuzzRepository(page: Page) {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.getByTestId("open-projects-view").click();
  await page.getByTestId("projects-section-projects").click();
  const projectEntry = page
    .locator(
      '[data-testid="project-card-buzz"], [data-testid="project-row-buzz"]',
    )
    .first();
  await expect(projectEntry).toBeVisible({ timeout: 10_000 });
  await projectEntry.click();
  await page.getByTestId("project-home-context-repo-buzz").click();
  return page.getByTestId("project-context-repository-actions");
}

test("Open app signs in to the repository's Buzz Pages site", async ({
  page,
}) => {
  await routeRelayInfo(page, PAGES_INFO);
  await installMockBridge(page, {
    projectRepoSnapshotExtraFiles: ["index.html"],
  });
  const actions = await openBuzzRepository(page);
  const openApp = actions.getByRole("button", { name: "Open app" });
  await expect(openApp).toBeVisible({ timeout: 10_000 });

  await waitForAnimations(page);
  await page
    .getByTestId("project-repository-actions-panel")
    .screenshot({ path: "test-results/screenshots/buzz-pages-open-app.png" });

  await openApp.click();
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.__TAURI_INTERNALS__.invoke("get_e2e_opened_external_urls"),
      ),
    )
    .toHaveLength(1);
  const [opened] = (await page.evaluate(() =>
    window.__TAURI_INTERNALS__.invoke("get_e2e_opened_external_urls"),
  )) as string[];
  const url = new URL(opened);
  expect(url.pathname).toBe("/_buzz/login");
  expect(url.hostname).toMatch(/^buzz--[0-9a-f]{16}\.apps\.localhost$/);
  expect(url.searchParams.get("next")).toBe("/");
  const event = JSON.parse(
    Buffer.from(url.searchParams.get("token") ?? "", "base64url").toString(),
  ) as { kind: number; tags: string[][] };
  expect(event.kind).toBe(27235);
  expect(event.tags).toContainEqual(["u", `${url.origin}/_buzz/login`]);
  expect(event.tags).toContainEqual(["method", "GET"]);
});

test("Open app stays hidden without a site or relay support", async ({
  page,
}) => {
  await routeRelayInfo(page, { supported_extensions: [] });
  await installMockBridge(page, {
    projectRepoSnapshotExtraFiles: ["index.html"],
  });
  const actions = await openBuzzRepository(page);
  await expect(actions.getByRole("button", { name: "Terminal" })).toBeVisible();
  await expect(actions.getByRole("button", { name: "Open app" })).toHaveCount(
    0,
  );
});
