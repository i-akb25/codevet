// Best-effort eager download at install time — NOT the only safety net
// anymore. Each scanner now calls ensureBinary() itself at runtime and
// self-heals if this never ran or was blocked (confirmed real: npm's
// "allowScripts" feature silently blocks this exact script by default on
// many machines). This means postinstall failing, being skipped, or
// simply not existing yet (e.g. a contributor's fresh clone before their
// first `npm run build`) is no longer a hard failure for the tool overall.
try {
  const { ensureBinary } = await import("../dist/scanners/ensureBinary.js");
  await ensureBinary("gitleaks");
  await ensureBinary("bearer");
} catch (err) {
  // dist/ may not exist yet (fresh clone, pre-build) or the download may
  // have failed/been blocked — either way, this is fine. The real
  // guarantee now lives in ensureBinary() being called again at the
  // moment a scan actually needs the binary.
  console.log(
    "[codevet] Skipped eager binary download at install time (this is fine — binaries download automatically on first use instead).",
  );
}
