import type { Ctx } from "../shared.js";

/** 认证 — 凭证与令牌 */
export const AuthnHandlers: Record<string, (ctx: Ctx) => Promise<number>> = {
  "cred-brute": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  const pairsFile = flags["pairs-file"];
  if (!url || !dir || typeof pairsFile !== "string") { console.error("usage: cred-brute <url> <outdir> --pairs-file F [--body-template '{\"email\":\"{USER}\",\"password\":\"{PASS}\"}'] [--delay-ms N]"); return 2; }
  const { probeCredBrute } = await import("../../domain/credBrute.js");
  const { readFile: rf } = await import("node:fs/promises");
  const pairs = JSON.parse(await rf(pairsFile, "utf8")) as { user: string; pass: string }[];
  const r = await probeCredBrute({ url, bodyTemplate: String(flags["body-template"] ?? "{}"), pairs, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), delayMs: num(flags["delay-ms"]) });
  out({ tried: r.tried, valid: r.valid.length, semantics: r.semantics, throttled: r.throttled, hits: r.valid.slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "otp-brute": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: otp-brute <url> <outdir> --body-template T [--samples N]   (T with {CODE} placeholder)"); return 2; }
  const { probeOtpBrute } = await import("../../domain/otpBrute.js");
  const r = await probeOtpBrute({ url, bodyTemplate: String(flags["body-template"] ?? "{}"), samples: num(flags.samples), outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ secretLeak: r.secretLeak, sent: r.sent, rateLimited: r.rateLimited, lockout: r.lockoutSigns.length, bruteForceable: r.bruteForceable, estimateSeconds: r.estimateSeconds, artifacts: r.artifacts });
  return 0;
  },
  "pass-policy": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: pass-policy <url> <outdir> --body-template '{\"email\":\"u{PASS}@x.io\",\"password\":\"{PASS}\"}'"); return 2; }
  const { probePassPolicy } = await import("../../domain/passPolicy.js");
  const r = await probePassPolicy({ url, bodyTemplate: String(flags["body-template"] ?? "{}"), outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, bearer: typeof flags.bearer === "string" ? flags.bearer : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ probed: r.probed, weakAccepted: r.weakAccepted.length, detail: r.weakAccepted.slice(0, 10), artifacts: r.artifacts });
  return 0;
  },
  "reset-abuse": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [resetUrl, loginUrl, dir] = positional;
  const answersFile = flags["answers-file"];
  if (!resetUrl || !loginUrl || !dir || typeof answersFile !== "string") { console.error("usage: reset-abuse <resetUrl> <loginUrl> <outdir> --answers-file F --email U --new-pass P [--reset-template T] [--login-template T]"); return 2; }
  const { probeResetAbuse } = await import("../../domain/resetAbuse.js");
  const { readFile: rf } = await import("node:fs/promises");
  const answers = (await rf(answersFile, "utf8")).split("\n").map(x => x.trim()).filter(Boolean);
  const r = await probeResetAbuse({ resetUrl, loginUrl, email: String(flags.email ?? ""), answers, newPass: String(flags["new-pass"] ?? "VelricProbe99!"), resetTemplate: String(flags["reset-template"] ?? '{"email":"{EMAIL}","answer":"{ANSWER}","new":"{NEWPASS}","repeat":"{NEWPASS}"}'), loginTemplate: String(flags["login-template"] ?? '{"email":"{EMAIL}","password":"{PASS}"}'), outputRoot: dir, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout) });
  out({ tried: r.tried, acceptedAnswers: r.acceptedAnswers, takeover: r.takeover, hashEcho: r.hashEcho, evidence: r.evidence, artifacts: r.artifacts });
  return 0;
  },
  "jwt-inspect": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const dir = positional[0];
  if (!dir) {
    console.error("usage: jwt-inspect <outdir> [--secrets FILE] [--js DIR] [--token STR]");
    return 2;
  }
  const { inspectJwt } = await import("../../domain/jwt.js");
  out(await inspectJwt({
    outputRoot: dir,
    secretsFile: typeof flags.secrets === "string" ? flags.secrets : undefined,
    jsDir: typeof flags.js === "string" ? flags.js : undefined,
    token: typeof flags.token === "string" ? flags.token : undefined,
  }));
  return 0;
  },
  "jwt-attack": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [token, endpoint, dir] = positional;
  if (!token || !endpoint || !dir) {
    console.error("usage: jwt-attack <token> <endpoint> <outdir> [--secrets-file FILE] [--candidates a,b] [--public-key-file F]");
    return 2;
  }
  const { probeJwtAttack } = await import("../../domain/jwtAttack.js");
  const cand = jarr(flags, "candidates");
  out(await probeJwtAttack({
    token, endpoint, outputRoot: dir,
    headers: await jobj<Record<string, string>>(flags, "headers"),
    proxy: await resolveProxy(flags),
    timeoutMs: num(flags.timeout),
    secretCandidates: cand,
    publicKeyPem: typeof flags["public-key-file"] === "string" ? await import("node:fs/promises").then(fs => fs.readFile(flags["public-key-file"] as string, "utf8")) : undefined,
  }));
  return 0;
  },
  "jwks-forge": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [token, oracleUrl, dir] = positional;
  if (!token || !oracleUrl || !dir) { console.error("usage: jwks-forge <token> <oracleUrl> <outdir> --jwks-url U [--elevate-json J]"); return 2; }
  const { probeJwksForge } = await import("../../domain/jwtJwksForge.js");
  let elevate: Record<string, unknown> | undefined;
  if (typeof flags["elevate-json"] === "string") { try { elevate = JSON.parse(flags["elevate-json"]) as Record<string, unknown>; } catch { console.error("bad --elevate-json"); return 2; } }
  const r = await probeJwksForge({ token, oracleUrl, jwksUrl: String(flags["jwks-url"] ?? "https://attacker-velric.example"), outputRoot: dir, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), elevate, kid: typeof flags.kid === "string" ? flags.kid : undefined });
  out({ supported: r.supported, forged: r.forged, evidence: r.evidence, artifacts: r.artifacts });
  return 0;
  },
  "login-replay": async (ctx) => {
    const { positional, flags, out, num, jarr, jobj, jarrObj, resolveProxy } = ctx;
  const [b, user, passArg, dir] = positional;
  // --pass-file reads the password from a file (0600) instead of argv,
  // where local users can see it in /proc.
  let pass = passArg;
  if (typeof flags["pass-file"] === "string") {
    const { readFile: rf } = await import("node:fs/promises");
    pass = (await rf(flags["pass-file"], "utf8")).trim();
  }
  if (!b || !user || !pass || !dir) { console.error("usage: login-replay <loginUrl> <user> <pass|--> <outdir> [--chromium PATH] [--pass-file F]"); return 2; }
  const { replayLogin } = await import("../../domain/loginReplay.js");
  out(await replayLogin({ baseUrl: b, username: user, password: pass, outputRoot: dir, chromiumPath: typeof flags.chromium === "string" ? flags.chromium : undefined, proxy: await resolveProxy(flags) }));
  return 0;
  },

  "admin-creds": async (ctx) => {
    const { positional, flags, out, num, jobj, jarr, resolveProxy } = ctx;
  const [url, dir] = positional;
  if (!url || !dir) { console.error("usage: admin-creds <baseUrl> <outdir> [--panels tomcat-manager,jenkins,...]"); return 2; }
  const { probeAdminCreds } = await import("../../domain/adminCreds.js");
  const r = await probeAdminCreds({ baseUrl: url, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), panels: jarr(flags, "panels") });
  out({ detected: r.detected, hits: r.hits, tried: r.tried, artifacts: r.artifacts });
  return r.hits.length ? 0 : 1;
  },
  "oauth-bypass": async (ctx) => {
    const { positional, flags, out, num, jobj, resolveProxy } = ctx;
  const [authz, redirect, dir] = positional;
  if (!authz || !redirect || !dir) { console.error("usage: oauth-bypass <authzUrl-with-{REDIRECT}> <legitRedirect> <outdir>"); return 2; }
  const { probeOAuthBypass } = await import("../../domain/oauthBypass.js");
  const r = await probeOAuthBypass({ authzUrl: authz, redirect, outputRoot: dir, cookie: typeof flags.cookie === "string" ? flags.cookie : undefined, headers: await jobj<Record<string, string>>(flags, "headers"), proxy: await resolveProxy(flags), timeoutMs: num(flags.timeout), pkce: flags.pkce !== false });
  out({ honest: r.honest, takeoverRisk: r.takeoverRisk, accepted: r.vectors.filter((v) => v.verdict === "accepted"), aux: r.aux, artifacts: r.artifacts });
  return r.takeoverRisk ? 0 : 1;
  },
};
