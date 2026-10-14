import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium } from "playwright-core";

/** Login auto-replay: detect a login form on the page, fill credentials,
 *  submit, and export the authenticated cookies so runtime capture /
 *  auth-probe can run logged-in without a hand-copied cookie string. */

export interface LoginReplayInput {
  readonly baseUrl: string;
  readonly username: string;
  readonly password: string;
  readonly outputRoot: string;
  readonly chromiumPath?: string;
  readonly proxy?: string;
  readonly timeoutMs?: number;
}

export interface LoginReplayResult {
  readonly baseUrl: string;
  readonly formFound: boolean;
  readonly submitted: boolean;
  /** Cookie header string ready for --cookie / capture_runtime cookies. */
  readonly cookieHeader: string | null;
  readonly landedUrl: string | null;
  readonly artifacts: { path: string; bytes: number }[];
}

const USER_SELECTORS = [
  "input[name=username]", "input[name=user]", "input[name=email]", "input[name=account]",
  "input[type=email]", "input[type=text][name*=user i]", "input[autocomplete=username]",
];
const PASS_SELECTORS = ["input[type=password][name*=pass i]", "input[type=password]"];

export const replayLogin = async (input: LoginReplayInput): Promise<LoginReplayResult> => {
  await mkdir(input.outputRoot, { recursive: true });
  const browser = await chromium.launch({
    executablePath: input.chromiumPath ?? "/usr/bin/chromium",
    headless: true,
    args: process.getuid?.() === 0 ? ["--no-sandbox", "--disable-dev-shm-usage"] : ["--disable-dev-shm-usage"],
  });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(input.baseUrl, { waitUntil: "domcontentloaded", timeout: input.timeoutMs ?? 45000 });
    await page.waitForTimeout(1500);

    let userSel: string | null = null;
    for (const sel of USER_SELECTORS) {
      if ((await page.locator(sel).count()) > 0) { userSel = sel; break; }
    }
    let passSel: string | null = null;
    for (const sel of PASS_SELECTORS) {
      if ((await page.locator(sel).count()) > 0) { passSel = sel; break; }
    }
    const formFound = userSel !== null && passSel !== null;
    if (!formFound) {
      const landedUrl = page.url(); // read before close — page is dead after close
      await browser.close();
      const r: LoginReplayResult = { baseUrl: input.baseUrl, formFound: false, submitted: false, cookieHeader: null, landedUrl, artifacts: [] };
      await writeFile(join(input.outputRoot, "login_replay.json"), JSON.stringify(r, null, 2));
      return r;
    }

    await page.locator(userSel!).fill(input.username);
    await page.locator(passSel!).fill(input.password);
    // Submit: form submit button → Enter → JS submit fallback.
    try {
      await Promise.all([
        page.waitForNavigation({ timeout: input.timeoutMs ?? 15000 }).catch(() => {}),
        page.locator("button[type=submit], input[type=submit], button:has-text('Sign in'), button:has-text('Log in'), button:has-text('登录')").first().click({ timeout: 5000 }),
      ]);
    } catch {
      await page.keyboard.press("Enter");
      await page.waitForTimeout(3000);
    }
    await page.waitForTimeout(2000);

    const cookies = await context.cookies();
    const cookieHeader = cookies.length > 0 ? cookies.map((c) => `${c.name}=${c.value}`).join("; ") : null;
    const submitted = cookies.length > 0;

    const result: LoginReplayResult = {
      baseUrl: input.baseUrl,
      formFound: true,
      submitted,
      cookieHeader,
      landedUrl: page.url(),
      artifacts: [],
    };
    const body = JSON.stringify({ ...result, cookieHeader: cookieHeader ? `${cookieHeader.slice(0, 30)}…` : null, cookies: cookies.map((c) => ({ name: c.name, domain: c.domain, secure: c.secure, httpOnly: c.httpOnly })) }, null, 2);
    await writeFile(join(input.outputRoot, "login_replay.json"), body);
    const path = join(input.outputRoot, "login_replay.json");
    result.artifacts.push({ path, bytes: Buffer.byteLength(body) });
    await browser.close();
    return result;
  } catch (e) {
    await browser.close().catch(() => {});
    throw e;
  }
};
