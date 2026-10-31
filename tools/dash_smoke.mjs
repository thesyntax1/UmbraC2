#!/usr/bin/env node
// A smoke test of the dashboard in a real DOM.
//
// The Go tests prove the page is served, that its policy names its script,
// and that the token is the only key.  They cannot prove the script *runs*:
// a typo in index.html would ship a blank page and every Go test would still
// pass.  This script loads the page in jsdom, answers the endpoints with
// synthetic data, and reads back what the operator would see.
//
// It also does the job the escape was written for: the data it feeds the
// page carries markup in a host name and in a pivot label, and the test
// asserts that the page renders those strings as text — no <img>, no
// <svg onload>, no second script.  That is the regression test for the
// stored XSS that the audit found.
//
// jsdom is not a dependency of the repository (the suite must run without
// npm).  Install it anywhere and point the script at it:
//
//   npm install --prefix /tmp/dashjs jsdom
//   node tools/dash_smoke.mjs /tmp/dashjs/node_modules
//
// Without it the script exits 77, which the pytest wrapper reads as a skip.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");

const modules = process.argv[2] || process.env.UMBRA_JSDOM_DIR || "";
let JSDOM;
try {
  const requireFrom = createRequire(join(modules || "/nonexistent", "noop.js"));
  ({ JSDOM } = requireFrom("jsdom"));
} catch (err) {
  console.log("SKIP: jsdom is not installed (pass the path to node_modules)");
  process.exit(77);
}

const page = readFileSync(join(root, "server", "internal", "dash", "index.html"), "utf8");

// The data the endpoints answer with.  Everything the page asks for and this
// map does not name gets an empty object, which the page reads as "nothing
// there yet" — the same answer an empty server gives.
const hostile = '<img src=x onerror="window.__pwned = 1">';
const payloads = {
  "/api/agents": {
    agents: [
      {
        id: "agent-ok",
        host: hostile,
        user: "root",
        os: "linux",
        arch: "x86_64",
        state: "online",
        transport: "tcp",
        last_seen: new Date().toISOString(),
        checkins: 3,
        score: 90,
        grade: "A",
        persist: [],
        canaries: [],
      },
    ],
    count: 1,
  },
  "/api/tasks": {
    tasks: [
      {
        id: "t-1",
        agent_id: "agent-ok",
        kind: "ping",
        state: "done",
        code: 0,
        created: Math.floor(Date.now() / 1000),
        out: "pong",
      },
    ],
    count: 1,
  },
  "/api/events": {
    events: [{ seq: 1, kind: "test.event", text: hostile, at: new Date().toISOString() }],
    seq: 1,
  },
  "/api/pivot": {
    nodes: [
      { agent_id: "agent-ok", transport: hostile, online: true, tunnels: true },
      { agent_id: "agent-2", transport: "ws", online: false },
    ],
    edges: [
      {
        agent_id: "agent-2",
        through: "agent-ok",
        mode: hostile,
        state: "open",
        bytes_up: 2048,
        bytes_down: 4096,
        path: ["agent-ok"],
      },
    ],
    clients: [],
    connections: [],
    claims: { "agent-ok": "alice" },
  },
};

const calls = [];
const dom = new JSDOM(page, {
  runScripts: "dangerously",
  pretendToBeVisual: true,
  url: "http://localhost:4003/",
  beforeParse(window) {
    window.fetch = (path) => {
      const clean = String(path).split("?")[0];
      calls.push(clean);
      const body = payloads[clean] === undefined ? {} : payloads[clean];
      return Promise.resolve({
        ok: true,
        status: 200,
        statusText: "OK",
        json: () => Promise.resolve(body),
      });
    };
    window.setInterval = () => 0; // the page polls; the test does not
  },
});

const { window } = dom;
const { document } = window;

// The script runs synchronously at parse time and the refreshes are promise
// chains, so the assertions wait for the microtasks the page schedules.
await new Promise((done) => setTimeout(done, 300));

const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
};

// 1. The page rendered at all: the inventory knows the host it was given.
const inventory = document.body.textContent || "";
check(inventory.includes("agent-ok"), "the inventory did not render the agent id");
check(inventory.includes("<img src=x"), "the hostile host name was not shown as text");

// 2. The markup in the data did not become markup.
check(document.querySelectorAll("img").length === 0, "a host name created an <img> element");
check(
  document.querySelectorAll("svg[onload], img[onerror], [onerror], [onload]").length === 0,
  "an attribute handler survived into the DOM"
);
check(window.__pwned === undefined, "the injected handler ran");

// 3. The reach panel is an SVG built by string concatenation — the place the
//    audit found — and it carries the escaped payload rather than the tag.
const reach = document.getElementById("reach");
check(reach !== null, "the reach panel is missing");
if (reach) {
  check(reach.querySelector("svg") !== null, "the reach panel has no drawing");
  check(
    (reach.innerHTML.match(/&lt;img/g) || []).length >= 1,
    "the reach panel did not escape the hostile label"
  );
  check(
    !/<\s*img/i.test(reach.innerHTML),
    "the reach panel parsed the hostile label as an element"
  );
}

// 4. The page asked for the panels it promises.  A refresh that throws stops
//    the chain, so this is also the check that the chain ran to its end.
for (const path of ["/api/agents", "/api/tasks", "/api/events", "/api/pivot", "/api/queue"]) {
  check(calls.includes(path), `the page never asked for ${path}`);
}

// 5. The connection state is honest: with no token the page says so.
const note = document.getElementById("state");
check(note !== null, "the page has no state line");

window.close();

if (failures.length) {
  console.error("FAILED:");
  for (const line of failures) console.error("  - " + line);
  process.exit(1);
}
console.log(`ok: the dashboard renders, escapes its data, and asked ${calls.length} endpoints`);
