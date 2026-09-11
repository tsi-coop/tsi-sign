package org.tsicoop.sign.app;

/**
 * The resolved identity of the App making a request (§6). Carries no
 * environment field — TEST vs. LIVE is a deployment-level property (§4.2),
 * never a per-request one.
 *
 * appSlug and rateLimitRpm extend the plan's literal (appId, appName)
 * shape: the storage key convention (§5) needs the slug, and per-app rate
 * limiting (§9, Chunk 9) needs the limit — resolving both here, since the
 * auth query already joins apps, avoids extra per-request DB round trips.
 * rateLimitRpm is null for "unlimited" (the default for every App).
 */
public record AppContext(
        String appId,
        String appName,
        String appSlug,
        Integer rateLimitRpm
) {
}
