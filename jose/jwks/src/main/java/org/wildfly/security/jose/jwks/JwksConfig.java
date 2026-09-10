/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.jose.jwks;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.function.Predicate;

import org.wildfly.security.jose.jwk.JWK;

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
    private final long cacheTtlMs;
    private final long minTimeBetweenRequestsMs;
    private final boolean preserveStaleOnFailure;

    private JwksConfig(Builder builder) {
        this.fetcher = builder.fetcher;
        this.keyFilter = builder.keyFilter;
        this.cacheTtlMs = builder.cacheTtlMs;
        this.minTimeBetweenRequestsMs = builder.minTimeBetweenRequestsMs;
        this.preserveStaleOnFailure = builder.preserveStaleOnFailure;
    }

    public JwksFetcher getFetcher() {
        return fetcher;
    }

    public Predicate<JWK> getKeyFilter() {
        return keyFilter;
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
            checkNotNullParam("keyFilter", keyFilter);
            return new JwksConfig(this);
        }
    }
}
