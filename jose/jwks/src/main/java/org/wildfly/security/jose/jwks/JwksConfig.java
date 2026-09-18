/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jose.jwks;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.function.Predicate;

import org.wildfly.security.jose.jwk.JWK;
import org.wildfly.security.jose.jwk.JsonWebKeySet;
import org.wildfly.security.jose.jwk.JsonWebKeySetUtil;
import org.wildfly.security.jose.util.JsonSerialization;

/**
 * Immutable configuration for a {@link JwksCache} instance.
 *
 * <p>All parameters are fixed at construction time via the {@link Builder}.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
public final class JwksConfig {

    private final JwksFetcher fetcher;
    private final Predicate<JWK> keyFilter;
    private final JwksKeySetParser keySetParser;
    private final long cacheTtlMs;
    private final long minTimeBetweenRequestsMs;
    private final boolean preserveStaleOnFailure;

    private JwksConfig(Builder builder) {
        this.fetcher = builder.fetcher;
        this.keyFilter = builder.keyFilter;
        this.keySetParser = builder.keySetParser != null ? builder.keySetParser : defaultKeySetParser(builder.keyFilter);
        this.cacheTtlMs = builder.cacheTtlMs;
        this.minTimeBetweenRequestsMs = builder.minTimeBetweenRequestsMs;
        this.preserveStaleOnFailure = builder.preserveStaleOnFailure;
    }

    private static JwksKeySetParser defaultKeySetParser(Predicate<JWK> keyFilter) {
        return rawBytes -> {
            JsonWebKeySet jwks = JsonSerialization.readValue(rawBytes, JsonWebKeySet.class);
            return JsonWebKeySetUtil.getKeys(jwks, keyFilter);
        };
    }

    public JwksFetcher getFetcher() {
        return fetcher;
    }

    public Predicate<JWK> getKeyFilter() {
        return keyFilter;
    }

    public JwksKeySetParser getKeySetParser() {
        return keySetParser;
    }

    public long getCacheTtlMs() {
        return cacheTtlMs;
    }

    public long getMinTimeBetweenRequestsMs() {
        return minTimeBetweenRequestsMs;
    }

    public boolean isPreserveStaleOnFailure() {
        return preserveStaleOnFailure;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private JwksFetcher fetcher;
        private Predicate<JWK> keyFilter;
        private JwksKeySetParser keySetParser;
        private long cacheTtlMs = 120_000;
        private long minTimeBetweenRequestsMs = 10_000;
        private boolean preserveStaleOnFailure = true;

        private Builder() {
        }

        public Builder fetcher(JwksFetcher fetcher) {
            this.fetcher = fetcher;
            return this;
        }

        public Builder keyFilter(Predicate<JWK> keyFilter) {
            this.keyFilter = keyFilter;
            return this;
        }

        /**
         * Overrides how a raw fetched response body is turned into the keys.
         * If not called, {@link JwksCache} parses the response as a JWKS (JSON Web Key Set).
         *
         * @param keySetParser the parsing strategy to use
         * @return this instance
         */
        public Builder keySetParser(JwksKeySetParser keySetParser) {
            this.keySetParser = keySetParser;
            return this;
        }

        public Builder cacheTtlMs(long cacheTtlMs) {
            this.cacheTtlMs = cacheTtlMs;
            return this;
        }

        public Builder minTimeBetweenRequestsMs(long minTimeBetweenRequestsMs) {
            this.minTimeBetweenRequestsMs = minTimeBetweenRequestsMs;
            return this;
        }

        public Builder preserveStaleOnFailure(boolean preserveStaleOnFailure) {
            this.preserveStaleOnFailure = preserveStaleOnFailure;
            return this;
        }

        public JwksConfig build() {
            checkNotNullParam("fetcher", fetcher);
            if (keySetParser == null) {
                // keyFilter is only meaningful for the default JWKS parsing strategy(non PEM)
                checkNotNullParam("keyFilter", keyFilter);
            }
            return new JwksConfig(this);
        }
    }
}
