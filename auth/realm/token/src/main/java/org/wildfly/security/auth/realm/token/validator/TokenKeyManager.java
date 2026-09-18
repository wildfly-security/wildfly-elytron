/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.auth.realm.token.validator;

import static org.wildfly.security.auth.realm.token._private.ElytronMessages.log;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import org.wildfly.security.jose.jwk.JsonWebKeySetUtil;
import org.wildfly.security.jose.jwks.JwksCache;
import org.wildfly.security.jose.jwks.JwksConfig;

/**
 * Owns every key-resolution strategy {@link JwtValidator} supports.
 *
 * <p>{@code jku} is accepted as a parameter rather than fixed configuration because
 * it comes from the token itself and varies per call.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
class TokenKeyManager {

    private final Set<String> allowedJkuValues;
    private final Map<String, PublicKey> namedKeys;
    private final PublicKey defaultPublicKey;
    private final URL jkuFallbackUrl;
    private final URL publicKeyUrl;
    private final JwksCache jwksCache;

    /** Backs {@link #publicKeyUrl}. A separate instance from {@link #jwksCache}: 
     * different content format (single PEM key, not a JWKS document). */
    private final JwksCache publicKeyUrlCache;

    TokenKeyManager(SSLContext sslContext, HostnameVerifier hostnameVerifier, long updateTimeout,
                    int connectionTimeout, int readTimeout, int minTimeBetweenRequests,
                    Set<String> allowedJkuValues, Map<String, PublicKey> namedKeys, PublicKey defaultPublicKey,
                    URL jkuFallbackUrl, URL publicKeyUrl) {
        this.allowedJkuValues = allowedJkuValues;
        this.namedKeys = namedKeys;
        this.defaultPublicKey = defaultPublicKey;
        this.jkuFallbackUrl = jkuFallbackUrl;
        this.publicKeyUrl = publicKeyUrl;

        HostnameVerifier hv = hostnameVerifier != null ? hostnameVerifier : HttpsURLConnection.getDefaultHostnameVerifier();

        if (sslContext != null) {
            this.jwksCache = new JwksCache(JwksConfig.builder()
                    .fetcher(new JdkJwksFetcher(sslContext, hv, connectionTimeout, readTimeout))
                    .keyFilter(JsonWebKeySetUtil.SUPPORTED_KEY_TYPE)
                    .cacheTtlMs(updateTimeout)
                    .minTimeBetweenRequestsMs(minTimeBetweenRequests)
                    .preserveStaleOnFailure(false)
                    .build());
        } else {
            log.tokenRealmJwtNoSSLIgnoringJku();
            this.jwksCache = null;
        }

        if (sslContext != null && publicKeyUrl != null) {
            this.publicKeyUrlCache = new JwksCache(JwksConfig.builder()
                    .fetcher(new JdkJwksFetcher(sslContext, hv, connectionTimeout, readTimeout))
                    .keySetParser(PemPublicKeySetParser.INSTANCE)
                    .cacheTtlMs(updateTimeout)
                    .minTimeBetweenRequestsMs(minTimeBetweenRequests)
                    .preserveStaleOnFailure(true)
                    .build());
        } else {
            this.publicKeyUrlCache = null;
        }

        if (allowedJkuValues.isEmpty()) {
            log.allowedJkuValuesNotConfigured();
        }
    }

    /**
     * {@code true} if any key source at all is configured — used by {@link JwtValidator} to decide
     * whether it should skip signature verification entirely (parser-only mode).
     */
    boolean hasAnyKeySource() {
        return defaultPublicKey != null || jwksCache != null || !namedKeys.isEmpty()
                || jkuFallbackUrl != null || publicKeyUrl != null;
    }

    /**
     * Resolves the public key that should be used to verify a token carrying the given {@code kid}
     * and {@code jku} header values (either may be {@code null}).
     *
     * @param kid the token's {@code kid} header value, or {@code null}
     * @param jku the token's {@code jku} header value, or {@code null}
     * @param forceRefresh if {@code true}, bypasses TTL-based cache freshness for whichever URL-backed
     *                      source ends up being consulted (still subject to that source's rate limiter)
     * @return the resolved public key, or {@code null} if none could be resolved
     */
    PublicKey resolve(String kid, String jku, boolean forceRefresh) {
        if (kid == null) {
            if (publicKeyUrlCache != null) {
                PublicKey remoteKey = publicKeyUrlCache.getAnyKey(publicKeyUrl, forceRefresh);
                if (remoteKey != null) {
                    return remoteKey;
                }
                log.debug("Could not resolve key via publicKeyUrl. Falling back to default public key.");
            }
            if (defaultPublicKey == null) {
                log.debug("Default public key not configured. Cannot validate token without kid claim.");
                return null;
            }
            return defaultPublicKey;
        }
        if (kid.isEmpty()) {
            log.debug("Empty kid claim. Cannot resolve key.");
            return null;
        }
        if (jku != null) {
            if (jwksCache == null) {
                log.debugf("Cannot validate token with jku [%s]. SSL is not configured and jku claim is not supported.", jku);
                return null;
            }
            if (!allowedJkuValues.contains(jku)) {
                log.debug("Cannot validate token, jku value is not allowed");
                return null;
            }
            try {
                return jwksCache.getPublicKey(kid, new URL(jku), forceRefresh);
            } catch (MalformedURLException e) {
                log.debug("Invalid jku URL.");
                return null;
            }
        } else {
            PublicKey res = namedKeys.get(kid);
            if (res != null) {
                return res;
            }
            if (jkuFallbackUrl != null) {
                if (jwksCache == null) {
                    log.debugf("Cannot use jku fallback URL [%s]. SSL is not configured.", jkuFallbackUrl);
                    return null;
                }
                if (!allowedJkuValues.contains(jkuFallbackUrl.toString())) {
                    log.debug("Cannot validate token, jku fallback URL is not allowed");
                    return null;
                }
                return jwksCache.getPublicKey(kid, jkuFallbackUrl, forceRefresh);
            }
            if (namedKeys.isEmpty()) {
                log.debug("Cannot validate token with kid claim.");
            } else {
                log.debug("Unknown kid.");
            }
            return null;
        }
    }
}
