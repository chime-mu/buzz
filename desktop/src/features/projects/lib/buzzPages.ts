/**
 * Buzz Pages: members-only static sites served from relay git repos.
 *
 * Each site has its own origin, `<repo>--<owner16>.<prefix><community-host>`,
 * so one site's scripts cannot read another. Signing in exchanges a NIP-98
 * event signed for the site's login URL for an HttpOnly session cookie on
 * that origin; the relay re-checks channel membership on every request.
 */

export type RelayPagesInfo = {
  pages?: {
    host_prefix?: string;
    login_path?: string;
  };
  supported_extensions?: string[];
};

export type RelayPagesCapability = {
  hostPrefix: string;
  loginPath: string;
};

/** Hex digits of the owner pubkey carried in a site label. */
const OWNER_PREFIX_LEN = 16;
/** DNS label length cap, less `--` and the owner prefix. */
const MAX_REPO_ID_LEN = 63 - 2 - OWNER_PREFIX_LEN;

/** The relay's advertised Buzz Pages capability, if any. */
export function relayPagesCapability(
  info: RelayPagesInfo,
): RelayPagesCapability | null {
  const hostPrefix = info.pages?.host_prefix;
  const loginPath = info.pages?.login_path;
  if (
    info.supported_extensions?.includes("buzz-pages") !== true ||
    typeof hostPrefix !== "string" ||
    !/^[a-z0-9-]{1,63}\.$/.test(hostPrefix) ||
    typeof loginPath !== "string" ||
    !/^(\/[A-Za-z0-9_-]+)+$/.test(loginPath)
  ) {
    return null;
  }
  return { hostPrefix, loginPath };
}

/**
 * Origin of a repository's site, or `null` when the repository cannot be a
 * site (its id is not a DNS-safe label, or the owner is not a hex pubkey).
 */
export function pagesSiteOrigin(
  relayOrigin: string,
  hostPrefix: string,
  owner: string,
  repoId: string,
): string | null {
  if (!/^[0-9a-f]{64}$/.test(owner)) return null;
  if (
    repoId.length === 0 ||
    repoId.length > MAX_REPO_ID_LEN ||
    !/^[a-z0-9-]+$/.test(repoId) ||
    repoId.startsWith("-") ||
    repoId.endsWith("-")
  ) {
    return null;
  }
  const label = `${repoId}--${owner.slice(0, OWNER_PREFIX_LEN)}`;
  // `--` at positions 3–4 is reserved for IDNA; CAs refuse such labels.
  if (label.slice(2, 4) === "--") return null;
  try {
    const relay = new URL(relayOrigin);
    const scheme =
      relay.protocol === "https:" || relay.protocol === "wss:"
        ? "https:"
        : "http:";
    return `${scheme}//${label}.${hostPrefix}${relay.host}`;
  } catch {
    return null;
  }
}

/**
 * Whether a repository looks like it publishes a site. The relay serves the
 * `pages` branch, else the default branch, so `files` only count when they
 * are the default branch's.
 */
export function repositoryPublishesSite(
  branchOptions: readonly string[],
  files: readonly { path: string }[],
  viewingDefaultBranch: boolean,
): boolean {
  return (
    branchOptions.includes("pages") ||
    (viewingDefaultBranch && files.some((file) => file.path === "index.html"))
  );
}

/** Base64url without padding, as the relay's login endpoint expects. */
function base64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * One-shot login URL for a site. `signedEventJson` must be a NIP-98 event
 * signed for `loginUrl` with method GET; the relay accepts it for 60 seconds.
 */
export function pagesLoginLink(
  loginUrl: string,
  signedEventJson: string,
  next = "/",
): string {
  const params = new URLSearchParams({
    token: base64Url(signedEventJson),
    next,
  });
  return `${loginUrl}?${params.toString()}`;
}
