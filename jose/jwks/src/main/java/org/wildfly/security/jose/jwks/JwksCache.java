/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.jose.jwks;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.jose.jwks.ElytronMessages.log;

import java.io.IOException;
import java.net.URL;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import org.wildfly.security.jose.jwk.JsonWebKeySet;
import org.wildfly.security.jose.jwk.JsonWebKeySetUtil;
import org.wildfly.security.jose.util.JsonSerialization;

/**
 * Unified JWKS thread-safe cache component to allow concurrent fetches.
 *
 * <p>Fetches JWKS documents from remote endpoints via a pluggable {@link JwksFetcher},
 * parses them using Jackson ({@code jose/jwk} classes), filters keys via a configurable
 * predicate, and caches the result per URL with configurable TTL and rate limiting.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
public class JwksCache {

    private final Map<URL, CacheEntry> entries = new LinkedHashMap<>();
    private final JwksConfig config;

    public JwksCache(JwksConfig config) {
        this.config = checkNotNullParam("config", config);
    }

    /**
     * Returns the {@link PublicKey} matching the given {@code kid} from the JWKS at {@code url},
     * fetching and caching as needed. Returns {@code null} if no matching key is found or if
     * {@code kid} is {@code null}. Callers wanting any available key regardless of kid should
     * use {@link #getAnyKey(URL)} instead.
     *
     * @param kid the key ID to look up
     * @param url the JWKS endpoint URL
     * @return the matching public key, or null
     */
    public PublicKey getPublicKey(String kid, URL url) {
        if (kid == null) {
            return null;
        }
        checkNotNullParam("url", url);

        CacheEntry cacheEntry = getOrCreateEntry(url);

        // ORDERING: Always prioritize an up-to-date map
        long lastFetchMs = cacheEntry.lastFetchTimeMs;
        Map<String, PublicKey> keys = cacheEntry.keys;
        long now = System.currentTimeMillis();

        if (!needsRefetch(keys, kid, lastFetchMs, now, config.getTtlBehavior())) {
            return keys.get(kid);
        }

        if (isRateLimited(lastFetchMs, now)) {
            log.jwksRateLimited(url, lastFetchMs);
            return keys.get(kid);
        }

        synchronized (cacheEntry) {
            keys = cacheEntry.keys;
            lastFetchMs = cacheEntry.lastFetchTimeMs;
            now = System.currentTimeMillis();

            if (!needsRefetch(keys, kid, lastFetchMs, now, config.getTtlBehavior())) {
                return keys.get(kid);
            }
            if (isRateLimited(lastFetchMs, now)) {
                return keys.get(kid);
            }

            fetchAndUpdate(cacheEntry, url, now);
            return cacheEntry.keys.get(kid);
        }
    }

    /**
     * Returns any available {@link PublicKey} from the JWKS at {@code url}, or {@code null}
     * if no keys are cached after a fetch attempt. Because there is no kid to check,
     * both {@link JwksConfig.TtlBehavior} values reduce to TTL-expiry-only behavior.
     *
     * @param url the JWKS endpoint URL
     * @return any available public key, or null
     */
    public PublicKey getAnyKey(URL url) {
        checkNotNullParam("url", url);

        CacheEntry cacheEntry = getOrCreateEntry(url);

        // ORDERING: Always prioritize an up-to-date map
        long lastFetchMs = cacheEntry.lastFetchTimeMs;
        Map<String, PublicKey> keys = cacheEntry.keys;
        long now = System.currentTimeMillis();

        if (!needsRefetch(keys, null, lastFetchMs, now, config.getTtlBehavior())) {
            return firstValue(keys);
        }

        if (isRateLimited(lastFetchMs, now)) {
            log.jwksRateLimited(url, lastFetchMs);
            return firstValue(keys);
        }

        synchronized (cacheEntry) {
            keys = cacheEntry.keys;
            lastFetchMs = cacheEntry.lastFetchTimeMs;
            now = System.currentTimeMillis();

            if (!needsRefetch(keys, null, lastFetchMs, now, config.getTtlBehavior())) {
                return firstValue(keys);
            }
            if (isRateLimited(lastFetchMs, now)) {
                return firstValue(keys);
            }

            fetchAndUpdate(cacheEntry, url, now);
            return firstValue(cacheEntry.keys);
        }
    }

    /**
     * Immediately re-fetches the JWKS from the given URL, bypassing rate limiting.
     * On success, the cache is updated atomically. On failure, stale keys are preserved.
     * If no cache entry exists for the URL, one is created.
     *
     * @param url the JWKS endpoint URL to reset
     */
    public void reset(URL url) {
        checkNotNullParam("url", url);

        CacheEntry cacheEntry = getOrCreateEntry(url);
        synchronized (cacheEntry) {
            fetchAndUpdate(cacheEntry, url, System.currentTimeMillis());
        }
    }

    private CacheEntry getOrCreateEntry(URL url) {
        synchronized (entries) {
            CacheEntry entry = entries.get(url);
            if (entry == null) {
                entry = new CacheEntry();
                entries.put(url, entry);
            }
            return entry;
        }
    }

    private boolean needsRefetch(Map<String, PublicKey> keys, String kid, long lastFetchMs, long now,
                                 JwksConfig.TtlBehavior ttlBehavior) {
        if (lastFetchMs == 0) {
            return true;
        }
        boolean ttlExpired = lastFetchMs + config.getCacheTtlMs() <= now;

        if (ttlBehavior == JwksConfig.TtlBehavior.UNCONDITIONAL) {
            return ttlExpired;
        }

        // KID_DEPENDENT: refetch if kid is missing OR TTL expired
        return (kid != null && !keys.containsKey(kid)) || ttlExpired;
    }

    private boolean isRateLimited(long lastFetchMs, long now) {
        return lastFetchMs > 0 && lastFetchMs + config.getMinTimeBetweenRequestsMs() > now;
    }

    private void fetchAndUpdate(CacheEntry cacheEntry, URL url, long now) {
        try {
            log.jwksFetchStarting(url);
            byte[] rawBytes = config.getFetcher().fetch(url);
            JsonWebKeySet jwks = JsonSerialization.readValue(rawBytes, JsonWebKeySet.class);
            Map<String, PublicKey> newKeys = JsonWebKeySetUtil.getKeys(jwks, config.getKeyFilter());

            // ORDERING: Always prioritize an up-to-date map
            cacheEntry.keys = Collections.unmodifiableMap(newKeys);
            cacheEntry.lastFetchTimeMs = now;
            log.jwksFetchSucceeded(url, newKeys.keySet());
        } catch (JwksException | IOException e) {
            log.jwksFetchFailed(url, e);
            if (!config.isPreserveStaleOnFailure()) {
                cacheEntry.keys = Collections.emptyMap();
            }
            cacheEntry.lastFetchTimeMs = now;
        }
    }

    private static PublicKey firstValue(Map<String, PublicKey> keys) {
        if (keys.isEmpty()) {
            return null;
        }
        Iterator<PublicKey> it = keys.values().iterator();
        return it.next();
    }

    // ORDERING: Always prioritize an up-to-date map
    private static class CacheEntry {
        volatile Map<String, PublicKey> keys = Collections.emptyMap();
        volatile long lastFetchTimeMs = 0;
    }
}
