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
