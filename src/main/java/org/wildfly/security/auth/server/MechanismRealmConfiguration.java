/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.server;

import org.wildfly.common.Assert;

/**
 * A configuration for a single mechanism realm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MechanismRealmConfiguration {
    private final String realmName;
    private final NameRewriter preRealmRewriter;
    private final NameRewriter postRealmRewriter;
    private final NameRewriter finalRewriter;
    private final RealmMapper realmMapper;

    /**
     * Construct a new instance.
     *
     * @param realmName the name of this realm (may not be {@code null})
     * @param preRealmRewriter the pre-realm rewriter to apply (may not be {@code null})
     * @param postRealmRewriter the post-realm rewriter to apply (may not be {@code null})
     * @param finalRewriter the final rewriter to apply (may not be {@code null})
     * @param realmMapper the realm mapper to use
     */
    MechanismRealmConfiguration(final String realmName, final NameRewriter preRealmRewriter, final NameRewriter postRealmRewriter, final NameRewriter finalRewriter, final RealmMapper realmMapper) {
        this.realmName = realmName;
        this.preRealmRewriter = preRealmRewriter;
        this.postRealmRewriter = postRealmRewriter;
        this.finalRewriter = finalRewriter;
        this.realmMapper = realmMapper;
    }

    /**
     * Get the mechanism realm name.
     *
     * @return the mechanism realm name (not {@code null})
     */
    public String getRealmName() {
        return realmName;
    }

    /**
     * Get the pre-realm rewriter for this mechanism realm.
     *
     * @return the pre-realm rewriter for this mechanism realm (not {@code null})
     */
    public NameRewriter getPreRealmRewriter() {
        return preRealmRewriter;
    }

    /**
     * Get the post-realm rewriter for this mechanism realm.
     *
     * @return the post-realm rewriter for this mechanism realm (not {@code null})
     */
    public NameRewriter getPostRealmRewriter() {
        return postRealmRewriter;
    }

    /**
     * Get the final rewriter for this mechanism realm.
     *
     * @return the final rewriter for this mechanism realm (not {@code null})
     */
    public NameRewriter getFinalRewriter() {
        return finalRewriter;
    }

    /**
     * Get the realm mapper for this mechanism realm.
     *
     * @return the realm mapper for this mechanism realm, or {@code null} to use the default
     */
    public RealmMapper getRealmMapper() {
        return realmMapper;
    }

    /**
     * A realm configuration for no particular realm, which does no additional rewriting.
     */
    public static final MechanismRealmConfiguration NO_REALM = new MechanismRealmConfiguration("none", null, null, null, null);

    /**
     * Obtain a new {@link Builder} capable of building a {@link MechanismRealmConfiguration}.
     *
     * @return a new {@link Builder} capable of building a {@link MechanismRealmConfiguration}.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String realmName;
        private NameRewriter preRealmRewriter;
        private NameRewriter postRealmRewriter;
        private NameRewriter finalRewriter;
        private RealmMapper realmMapper;

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        public Builder setRealmName(final String realmName) {
            this.realmName = realmName;

            return this;
        }

        public Builder setPreRealmRewriter(final NameRewriter preRealmRewriter) {
            this.preRealmRewriter = preRealmRewriter;

            return this;
        }

        public Builder setPostRealmRewriter(final NameRewriter postRealmRewriter) {
            this.postRealmRewriter = postRealmRewriter;

            return this;
        }

        public Builder setFinalRewriter(final NameRewriter finalRewriter) {
            this.finalRewriter = finalRewriter;

            return this;
        }

        public Builder setRealmMapper(final RealmMapper realmMapper) {
            this.realmMapper = realmMapper;
            return this;
        }

        public MechanismRealmConfiguration build() {
            Assert.checkNotNullParam("realmName", realmName);
            return new MechanismRealmConfiguration(realmName, preRealmRewriter, postRealmRewriter, finalRewriter, realmMapper);
        }
    }
}
