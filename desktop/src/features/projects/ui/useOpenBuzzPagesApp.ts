import { useQuery } from "@tanstack/react-query";
import { openUrl } from "@tauri-apps/plugin-opener";
import * as React from "react";
import { toast } from "sonner";

import type { Repository } from "@/features/projects/hooks";
import {
  pagesLoginLink,
  pagesSiteOrigin,
  type RelayPagesInfo,
  relayPagesCapability,
} from "@/features/projects/lib/buzzPages";
import { signRelayEvent } from "@/shared/api/tauri";
import { useRelayOrigin } from "@/shared/lib/useRelayOrigin";

const NIP98_KIND = 27235;

async function fetchRelayPagesCapability(
  relayOrigin: string,
  signal: AbortSignal,
) {
  const response = await fetch(`${relayOrigin.replace(/\/+$/, "")}/info`, {
    headers: { Accept: "application/nostr+json" },
    signal,
  });
  if (!response.ok) {
    throw new Error(`Could not read relay capabilities (${response.status})`);
  }
  return relayPagesCapability((await response.json()) as RelayPagesInfo);
}

/**
 * Opens a Buzz-hosted repository's Buzz Pages site in the browser, signed in
 * as the current identity. Returns `null` when the relay does not serve
 * Pages or the repository cannot be a site.
 */
export function useOpenBuzzPagesApp(
  repository: Pick<Repository, "dtag" | "owner"> | null | undefined,
): (() => Promise<void>) | null {
  const relayOrigin = useRelayOrigin();
  const capabilityQuery = useQuery({
    enabled: Boolean(relayOrigin),
    queryFn: ({ signal }) =>
      fetchRelayPagesCapability(relayOrigin as string, signal),
    queryKey: ["relay-capability", relayOrigin, "buzz-pages"],
    retry: 1,
    staleTime: 5 * 60 * 1_000,
  });
  const capability = capabilityQuery.data ?? null;
  const siteOrigin =
    capability && relayOrigin && repository
      ? pagesSiteOrigin(
          relayOrigin,
          capability.hostPrefix,
          repository.owner,
          repository.dtag,
        )
      : null;
  const loginPath = capability?.loginPath;

  const openApp = React.useCallback(async () => {
    if (!siteOrigin || !loginPath) return;
    const loginUrl = `${siteOrigin}${loginPath}`;
    try {
      const signedEvent = await signRelayEvent({
        kind: NIP98_KIND,
        content: "",
        tags: [
          ["u", loginUrl],
          ["method", "GET"],
        ],
      });
      await openUrl(pagesLoginLink(loginUrl, JSON.stringify(signedEvent)));
    } catch {
      toast.error("Couldn’t open app", {
        description: "Buzz could not sign you in to this repository’s app.",
      });
    }
  }, [loginPath, siteOrigin]);

  return siteOrigin ? openApp : null;
}
