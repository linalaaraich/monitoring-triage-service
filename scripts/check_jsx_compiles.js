// JSX compile gate — every .jsx under app/static/design must parse with the
// SAME compiler the browser uses (@babel/standalone, preset "react").
//
// Why this exists (2026-06-12): commit 7664ec0 shipped a stray `))}` in
// detail.jsx. Babel-standalone failed in the browser, React never mounted,
// and EVERY individual alert page rendered blank while still returning
// HTTP 200 — invisible to curl-based smoke checks and to the Python suite.
// A syntax error in any shared file (atoms/sidebar) blanks every page that
// loads it, so the gate compiles all files and reports every failure.
//
// Usage: node scripts/check_jsx_compiles.js [designDir]
// Resolution: @babel/standalone from normal NODE_PATH / local node_modules.
"use strict";
const fs = require("fs");
const path = require("path");

let Babel;
try {
  Babel = require("@babel/standalone");
} catch (e) {
  console.error(
    "check_jsx_compiles: @babel/standalone not resolvable — " +
      "run `npm install --no-save @babel/standalone` first (CI does)."
  );
  process.exit(2);
}

const dir =
  process.argv[2] || path.join(__dirname, "..", "app", "static", "design");
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".jsx"));
if (files.length === 0) {
  console.error(`check_jsx_compiles: no .jsx files found in ${dir}`);
  process.exit(2);
}

let failed = 0;
for (const f of files) {
  try {
    Babel.transform(fs.readFileSync(path.join(dir, f), "utf8"), {
      presets: ["react"],
    });
    console.log(`OK   ${f}`);
  } catch (e) {
    failed += 1;
    console.error(`FAIL ${f} — ${e.message.split("\n")[0]}`);
  }
}
process.exit(failed === 0 ? 0 : 1);
