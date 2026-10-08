// Browser-driven SSO session capture, for servers where the only login path is
// an external IdP (e.g. GitLab) and the user is NOT an admin — so Personal Access
// Tokens and OAuth2 apps (both admin-gated) are unavailable.
//
// A pure loopback callback can't work here: the GitLab SSO redirect_uri is fixed
// to `{MM_URL}/signup/gitlab/complete`, and the session lands as the `MMAUTHTOKEN`
// cookie on the Mattermost origin — never on 127.0.0.1. So instead we drive a real
// browser (puppeteer-core + the system Chrome), let the user complete the SSO login
// in it, then read the session cookie out of that browser via CDP. This is exactly
// what the Mattermost Desktop app does (Electron reads its webview's cookie).
//
// puppeteer-core is imported lazily (dynamic import) so the MCP server path — which
// never touches a browser — pays no startup cost for it.
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { defaultChromiumExecutable } from "./default-browser.js";
import { log } from "../log.js";

/** Mattermost's session cookie. Its value is a valid Bearer token for the v4 API. */
const COOKIE_NAME = "MMAUTHTOKEN";
/** How long to wait for the user to finish the interactive SSO login. */
const CAPTURE_TIMEOUT_MS = 300_000; // 5 min
const POLL_INTERVAL_MS = 800;

// --- Chrome discovery --------------------------------------------------------

const MAC_CANDIDATES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
];

const LINUX_BINARIES = [
  "google-chrome",
  "google-chrome-stable",
  "chromium",
  "chromium-browser",
  "brave-browser",
  "microsoft-edge",
  "microsoft-edge-stable",
];

function winCandidates(env: Record<string, string | undefined>): string[] {
  const roots = [env.PROGRAMFILES, env["PROGRAMFILES(X86)"], env.LOCALAPPDATA].filter(
    (r): r is string => Boolean(r),
  );
  const rel = [
    "Google\\Chrome\\Application\\chrome.exe",
    "Microsoft\\Edge\\Application\\msedge.exe",
    "BraveSoftware\\Brave-Browser\\Application\\brave.exe",
  ];
  return roots.flatMap((root) => rel.map((p) => `${root}\\${p}`));
}

function firstNonEmpty(...vals: (string | undefined)[]): string | undefined {
  for (const v of vals) {
    if (v && v.trim()) return v.trim();
  }
  return undefined;
}

function defaultWhich(bin: string): string | null {
  try {
    const out = execFileSync("which", [bin], { encoding: "utf8" }).trim();
    return out || null;
  } catch {
    return null; // not on PATH
  }
}

/**
 * Locate a Chrome/Chromium executable for puppeteer-core (which ships no browser).
 * Honors MM_CHROME_PATH / PUPPETEER_EXECUTABLE_PATH / CHROME_PATH, then well-known
 * install locations per platform. The `fileExists`/`which` seams keep it testable.
 */
export function resolveChromePath(
  env: Record<string, string | undefined> = process.env,
  platform: string = process.platform,
  fileExists: (p: string) => boolean = existsSync,
  which: (bin: string) => string | null = defaultWhich,
  detectDefault: (platform: string) => string | null = (p) => defaultChromiumExecutable(p),
): string {
  const override = firstNonEmpty(
    env.MM_CHROME_PATH,
    env.PUPPETEER_EXECUTABLE_PATH,
    env.CHROME_PATH,
  );
  if (override) {
    if (fileExists(override)) return override;
    throw new Error(`Chrome path from the environment does not exist: ${override}`);
  }

  // Prefer the user's default browser when it is Chromium-based.
  const preferred = detectDefault(platform);
  if (preferred && fileExists(preferred)) return preferred;

  const candidates =
    platform === "darwin" ? MAC_CANDIDATES : platform === "win32" ? winCandidates(env) : [];
  for (const candidate of candidates) {
    if (fileExists(candidate)) return candidate;
  }

  if (platform === "linux") {
    for (const bin of LINUX_BINARIES) {
      const found = which(bin);
      if (found) return found;
    }
  }

  throw new Error(
    "Could not find a Chrome/Chromium executable. Install Google Chrome, or set " +
      "MM_CHROME_PATH to the browser executable.",
  );
}

// --- Session capture ---------------------------------------------------------

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

interface CdpSession {
  send(method: "Network.enable"): Promise<unknown>;
  send(
    method: "Network.getCookies",
    params: { urls: string[] },
  ): Promise<{ cookies: { name: string; value: string }[] }>;
}

async function readSessionCookie(cdp: CdpSession, url: string): Promise<string | null> {
  try {
    const { cookies } = await cdp.send("Network.getCookies", { urls: [url] });
    const match = cookies.find((c) => c.name === COOKIE_NAME && c.value);
    return match?.value ?? null;
  } catch {
    return null; // browser closing / transient — caller re-checks state
  }
}

/**
 * Open `{url}/login` in the system browser, wait for the user to complete the SSO
 * login, and return the resulting `MMAUTHTOKEN` session token. Throws if the browser
 * is closed early or the login is not completed within {@link CAPTURE_TIMEOUT_MS}.
 */
export async function captureSessionToken(
  url: string,
  timeoutMs: number = CAPTURE_TIMEOUT_MS,
): Promise<string> {
  const executablePath = resolveChromePath();
  const { default: puppeteer } = await import("puppeteer-core");

  log(`launching browser: ${executablePath}`);
  const browser = await puppeteer.launch({
    headless: false,
    executablePath,
    defaultViewport: null,
    args: ["--no-first-run", "--no-default-browser-check"],
  });

  let disconnected = false;
  browser.on("disconnected", () => {
    disconnected = true;
  });

  try {
    const pages = await browser.pages();
    const page = pages[0] ?? (await browser.newPage());
    // Mobile user agent so the server tags this as a mobile session for longer lifetime
    await page.setUserAgent("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36 Mattermost/2.18.0");
    await page.goto(`${url}/login/sso/saml`, { waitUntil: "domcontentloaded" });
    const cdp = (await page.createCDPSession()) as unknown as CdpSession;
    await cdp.send("Network.enable"); // ensure Network.getCookies is serviced

    log(`browser opened at ${url}/login/sso/saml — complete the SSO login in that window…`);

    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (disconnected) throw new Error("Browser was closed before the login completed.");
      if (Date.now() > deadline) {
        throw new Error(`Timed out after ${Math.round(timeoutMs / 1000)}s waiting for the login.`);
      }
      const token = await readSessionCookie(cdp, url);
      if (token) return token;
      await sleep(POLL_INTERVAL_MS);
    }
  } finally {
    if (!disconnected) await browser.close().catch(() => {});
  }
}
