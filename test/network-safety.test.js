// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { assertRemoteHostAllowed, isPrivateAddress, parseRemoteUrl, safeFetch } from "../src/lib/network-safety.js";
import { withServer } from "./helpers.js";

test("private, link-local, and metadata addresses are classified and blocked", async () => {
  for (const address of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "fc00::1", "fe80::1"]) {
    assert.equal(isPrivateAddress(address), true);
  }
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  await assert.rejects(assertRemoteHostAllowed("metadata.google.internal"), { code: "PRIVATE_HOST" });
  await assert.rejects(assertRemoteHostAllowed("127.0.0.1"), { code: "PRIVATE_HOST" });
  await assert.doesNotReject(assertRemoteHostAllowed("127.0.0.1", { allowPrivateHosts: true }));
});

test("safe fetch rechecks redirect hops and caps redirects", async () => {
  await withServer(
    (request, response) => {
      if (request.url === "/private") {
        response.writeHead(302, { location: "http://127.0.0.1:9/blocked" });
      } else {
        response.writeHead(302, { location: "/again" });
      }
      response.end();
    },
    async (url) => {
      await assert.rejects(safeFetch(`${url}/private`, {}, { allowPrivateHosts: false }), { code: "PRIVATE_HOST" });
      await assert.rejects(safeFetch(`${url}/again`, {}, { allowPrivateHosts: true, maxRedirects: 1 }), { code: "NETWORK" });
    }
  );
});

test("only absolute HTTP URLs are accepted", () => {
  assert.equal(parseRemoteUrl("https://example.com").hostname, "example.com");
  assert.throws(() => parseRemoteUrl("file:///etc/passwd"), { code: "UNSAFE_URL" });
  assert.throws(() => parseRemoteUrl("https://user:secret@example.com"), { code: "UNSAFE_URL" });
});
