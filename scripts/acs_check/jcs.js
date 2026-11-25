// RFC 8785 oracle for scripts/acs_check/acs_check.py. Offline, no dependency.
//
// Numbers and strings are serialised by Node's JSON.stringify, which is the ECMAScript
// Number-to-String rule that RFC 8785 requires. Object keys are sorted by UTF-16 code unit,
// which is what Array.prototype.sort does on strings. NaN and Infinity are refused.
//
// Input on stdin: a JSON array of JSON texts. Output on stdout: a JSON array with one
// {"ok": true, "text": ...} or {"ok": false, "error": ...} per input text.

function serialise(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(serialise).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + serialise(value[k])).join(",") + "}";
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  let texts;
  try {
    texts = JSON.parse(input);
    if (!Array.isArray(texts)) throw new Error("input must be a JSON array of texts");
  } catch (e) {
    process.stderr.write("jcs.js: " + e.message + "\n");
    process.exit(2);
  }
  const out = texts.map((text) => {
    try {
      return { ok: true, text: serialise(JSON.parse(text)) };
    } catch (e) {
      return { ok: false, error: String(e.message) };
    }
  });
  process.stdout.write(JSON.stringify(out));
});
