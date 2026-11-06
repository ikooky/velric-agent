import { chromium } from "playwright-core";
import { ensureDir, writeArtifact } from "../adapters/artifacts.js";
import { sameOrigin } from "../core/credentials.js";
import { observeBrowserRequests } from "../application/runtime.js";
import { writeOwnedManifest } from "../application/harvest.js";

export interface LoginReplayInput {
  readonly baseUrl: string;
  readonly username: string;
  readonly password: string;
  readonly outputRoot: string;
  readonly chromiumPath?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
  readonly loggedInRegex?: string;
  readonly loggedOutRegex?: string;
  readonly authCheckUrl?: string;
}
export interface LoginReplayResult {
  readonly baseUrl: string;
  readonly formFound: boolean;
  /** Submission occurred, independently of the authentication oracle. */
  readonly submitted: boolean;
  readonly authenticated: boolean;
  readonly authentication: "verified" | "rejected" | "inconclusive";
  readonly authEvidence: string[];
  readonly cookieHeader: string | null;
  readonly landedUrl: string | null;
  readonly artifacts: { path: string; bytes: number }[];
}
const USER_SELECTORS = ["input[name=username]", "input[name=user]", "input[name=email]", "input[name=account]", "input[type=email]", "input[type=text][name*=user i]", "input[autocomplete=username]"];
const PASS_SELECTORS = ["input[type=password][name*=pass i]", "input[type=password]"];

export const replayLogin = async (input: LoginReplayInput): Promise<LoginReplayResult> => {
  await ensureDir(input.outputRoot);
  const base = new URL(input.baseUrl);
  const browser = await chromium.launch({ executablePath: input.chromiumPath ?? "/usr/bin/chromium", headless: true,
    args: process.getuid?.() === 0 ? ["--no-sandbox", "--disable-dev-shm-usage"] : ["--disable-dev-shm-usage"], ...(input.proxy ? { proxy: { server: input.proxy } } : {}) });
  try {
    const context = await browser.newContext();
    await context.route('**/*', route => sameOrigin(route.request().url(), base.href) ? route.continue() : route.abort('blockedbyclient'));
    const page = await context.newPage(), network = observeBrowserRequests(page);
    const timeout = input.timeoutMs ?? 15000;
    await page.goto(base.href, { waitUntil: 'domcontentloaded', timeout });
    const firstMatch = async (selectors: string[]): Promise<string | null> => {
      for (const selector of selectors) if (await page.locator(selector).count()) return selector;
      return null;
    };
    const user = await firstMatch(USER_SELECTORS), pass = await firstMatch(PASS_SELECTORS);
    const formFound = !!user && !!pass;
    const pre = await context.cookies(base.href), evidence: string[] = [];
    let submitted = false, authentication: LoginReplayResult['authentication'] = 'inconclusive';
    if (formFound) {
      await page.locator(user!).first().fill(input.username);
      await page.locator(pass!).first().fill(input.password);
      const button = page.locator("button[type=submit], input[type=submit], button:has-text('Sign in'), button:has-text('Log in'), button:has-text('登录')").first();
      await Promise.all([
        page.waitForURL(url => url.href !== base.href, { timeout }).catch(() => undefined),
        (await button.count() ? button.click({ timeout }) : page.locator(pass!).first().press('Enter')).then(() => { submitted = true; }).catch((err) => {
          evidence.push(`submit failed: ${err instanceof Error ? err.message : String(err)}`);
        }),
      ]);
      if (input.loggedInRegex || input.loggedOutRegex) await page.waitForFunction(`() => {
        const text=document.body ? document.body.innerText : '';
        return ${input.loggedInRegex ? `new RegExp(${JSON.stringify(input.loggedInRegex)}).test(text)` : 'false'} || ${input.loggedOutRegex ? `new RegExp(${JSON.stringify(input.loggedOutRegex)}).test(text)` : 'false'};
      }`, undefined, { timeout }).catch(() => undefined);
      if (input.authCheckUrl) {
        const check = new URL(input.authCheckUrl, base).href;
        if (!sameOrigin(check, base.href)) throw new Error('authCheckUrl must be same-origin');
        await page.goto(check, { waitUntil: 'domcontentloaded', timeout });
      }
    }
    const landedUrl = page.url(), cookies = await context.cookies(base.href);
    const text = await page.locator('body').innerText().catch(() => '');
    const stillLogin = await page.locator('input[type=password]').count() > 0;
    const changed = cookies.filter(c => pre.find(p => p.name === c.name && p.domain === c.domain && p.path === c.path)?.value !== c.value);
    const sessionChanged = changed.some(c => /sess|token|auth|sid|jwt|login/i.test(c.name));
    if (sessionChanged) evidence.push('session-credential-changed');
    // Cookie value rotation and navigation are recorded as candidates only.
    // A caller-supplied authenticated marker or a logged-in UI control verifies.
    if (input.loggedOutRegex && new RegExp(input.loggedOutRegex).test(text) || /invalid credentials|incorrect password|login failed/i.test(text)) authentication = 'rejected';
    else if (sameOrigin(landedUrl, base.href) && !stillLogin && submitted) {
      if (input.loggedInRegex && new RegExp(input.loggedInRegex).test(text)) { authentication = 'verified'; evidence.push('authenticated-marker'); }
      else if (!input.loggedInRegex && await page.locator('a[href*=logout i], form[action*=logout i], [data-authenticated=true]').count()) { authentication = 'verified'; evidence.push('authenticated-ui-control'); }
    }
    if (authentication === 'inconclusive' && stillLogin && submitted) authentication = 'rejected';
    await network.drain(); network.close();
    const authenticated = authentication === 'verified';
    const result: LoginReplayResult = { baseUrl: input.baseUrl, formFound, submitted, authenticated, authentication, authEvidence: evidence,
      cookieHeader: authenticated && cookies.length ? cookies.map(c => `${c.name}=${c.value}`).join('; ') : null, landedUrl, artifacts: [] };
    // No credential prefix is persisted: even a shortened session token is secret.
    result.artifacts.push(await writeArtifact(input.outputRoot, 'login_replay.json', JSON.stringify({ ...result, cookieHeader: authenticated ? '[redacted]' : null,
      cookies: cookies.map(c => ({ name: c.name, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly })) }, null, 2)));
    result.artifacts.push(await writeOwnedManifest(input.outputRoot, 'login_replay_manifest.json', 'login-replay', base.href, result.artifacts, authenticated ? 1 : 0));
    return result;
  } finally { await browser.close(); }
};
