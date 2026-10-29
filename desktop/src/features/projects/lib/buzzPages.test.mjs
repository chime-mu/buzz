import assert from "node:assert/strict";
import { test } from "node:test";

import {
  pagesLoginLink,
  pagesSiteOrigin,
  relayPagesCapability,
  repositoryPublishesSite,
} from "./buzzPages.ts";

const OWNER =
  "fabe1ffc0a550dcb33a083cb36a120d975a429ce518e32508dda6a075b4c4e18";

test("reads the advertised capability and rejects unsafe values", () => {
  const info = {
    pages: { host_prefix: "apps.", login_path: "/_buzz/login" },
    supported_extensions: ["buzz-pages"],
  };
  assert.deepEqual(relayPagesCapability(info), {
    hostPrefix: "apps.",
    loginPath: "/_buzz/login",
  });
  assert.equal(relayPagesCapability({ pages: info.pages }), null);
  for (const host_prefix of ["apps", "a.b.", "evil.com/", ""]) {
    assert.equal(
      relayPagesCapability({ ...info, pages: { ...info.pages, host_prefix } }),
      null,
    );
  }
  for (const login_path of ["//evil", "/x?y", "https://evil/"]) {
    assert.equal(
      relayPagesCapability({ ...info, pages: { ...info.pages, login_path } }),
      null,
    );
  }
});

test("builds one origin per repository, matching the relay", () => {
  assert.equal(
    pagesSiteOrigin("https://buzz.mu.dk", "apps.", OWNER, "team-dash"),
    "https://team-dash--fabe1ffc0a550dcb.apps.buzz.mu.dk",
  );
  assert.equal(
    pagesSiteOrigin("http://localhost:3000", "apps.", OWNER, "x"),
    "http://x--fabe1ffc0a550dcb.apps.localhost:3000",
  );
  for (const repo of [
    "Team",
    "team_dash",
    "-x",
    "x-",
    "a.b",
    "",
    "a".repeat(46),
    "ui",
    "ab--x",
  ]) {
    assert.equal(
      pagesSiteOrigin("https://b.example", "apps.", OWNER, repo),
      null,
    );
  }
  assert.equal(pagesSiteOrigin("https://b.example", "apps.", "ABC", "x"), null);
});

test("detects repositories that publish a site", () => {
  const index = [{ path: "index.html" }];
  assert.equal(repositoryPublishesSite(["main", "pages"], [], false), true);
  assert.equal(repositoryPublishesSite(["main"], index, true), true);
  // The relay serves the default branch, not the one being viewed.
  assert.equal(repositoryPublishesSite(["main", "feat"], index, false), false);
  assert.equal(
    repositoryPublishesSite(["main"], [{ path: "docs/index.html" }], true),
    false,
  );
});

test("encodes the signed event as an unpadded base64url token", () => {
  const event = JSON.stringify({ kind: 27235, content: "ü?" });
  const link = pagesLoginLink("https://s.example/_buzz/login", event, "/a b");
  const url = new URL(link);
  assert.equal(url.origin + url.pathname, "https://s.example/_buzz/login");
  const token = url.searchParams.get("token");
  assert.match(token, /^[A-Za-z0-9_-]+$/);
  assert.equal(Buffer.from(token, "base64url").toString("utf8"), event);
  assert.equal(url.searchParams.get("next"), "/a b");
});
