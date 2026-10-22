// This network probe exercises bundled DNS/TLS support without GitHub credentials.
if (process.argv.includes("--self-test")) {
  void fetch("https://api.github.com/", { signal: AbortSignal.timeout(10_000) })
    .then((response) => {
      if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
      console.log("Bundled Node runtime, DNS, and HTTPS: OK");
    })
    .catch(() => { console.error("HTTPS self-test failed"); process.exitCode = 1; });
} else {
  void import("../src/main.js");
}
