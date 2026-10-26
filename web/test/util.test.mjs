import { test } from "node:test";
import assert from "node:assert/strict";
import { safeNext, joinPath, parentPath, fileURL, kindOf } from "../util.js";

const origin = "https://box.example:8443";

test("only a file path on this server is followed after logging in", () => {
  const ok = (next) => safeNext(`?next=${encodeURIComponent(next)}`, origin);
  assert.equal(ok("/files/public/a.txt"), "/files/public/a.txt");
  assert.equal(ok("/files/public/a%20b.txt?download"), "/files/public/a%20b.txt?download");
  for (const bad of ["/\\evil.example/", "/\t/evil.example/", "//evil.example/files/x", "https://evil.example/files/x",
    "/files/../api/admin/users/list", "/files/%2e%2e/api/x", "/api/files", "files/x", "", "javascript:alert(1)", "/files\\..\\x"]) {
    assert.equal(ok(bad), null, bad);
  }
  assert.equal(safeNext("", origin), null);
});

test("paths and file addresses", () => {
  assert.equal(joinPath("", "a"), "a");
  assert.equal(joinPath("a/b", "c"), "a/b/c");
  assert.equal(parentPath("a/b/c"), "a/b");
  assert.equal(parentPath("a"), "");
  assert.equal(fileURL("a b/c#?%.txt"), "/files/a%20b/c%23%3F%25.txt");
  assert.equal(fileURL("x.mp4", true), "/files/x.mp4?download");
  assert.equal(kindOf("Clip.WEBM"), "video");
  assert.equal(kindOf("noext"), "other");
});
