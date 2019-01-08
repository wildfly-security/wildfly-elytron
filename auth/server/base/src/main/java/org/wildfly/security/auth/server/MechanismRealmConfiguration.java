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

import java.security.Principal;
import java.util.function.Function;

import org.wildfly.common.Assert;

/**
 * A configuration for a single mechanism realm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MechanismRealmConfiguration {
    private final String realmName;
    private final Function<Principal, Principal> preRealmRewriter;
    private final Function<Principal, Principal> postRealmRewriter;
    private final Function<Principal, Principal> finalRewriter;
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
    MechanismRealmConfiguration(final String realmName, final Function<Principal, Principal> preRealmRewriter, final Function<Principal, Principal> postRealmRewriter, final Function<Principal, Principal> finalRewriter, final RealmMapper realmMapper) {
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
    public Function<Principal, Principal> getPreRealmRewriter() {
        return preRealmRewriter;
    }

    /**
     * Get the post-realm rewriter for this mechanism realm.
     *
     * @return the post-realm rewriter for this mechanism realm (not {@code null})
     */
    public Function<Principal, Principal> getPostRealmRewriter() {
        return postRealmRewriter;
    }

    /**
     * Get the final rewriter for this mechanism realm.
     *
     * @return the final rewriter for this mechanism realm (not {@code null})
     */
    public Function<Principal, Principal> getFinalRewriter() {
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
    public static final MechanismRealmConfiguration NO_REALM = new MechanismRealmConfiguration("none", Function.identity(), Function.identity(), Function.identity(), null);

    /**
     * Obtain a new {@link Builder} capable of building a {@link MechanismRealmConfiguration}.
     *
     * @return a new {@link Builder} capable of building a {@link MechanismRealmConfiguration}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for mechanism realm configuration.
     */
    public static final class Builder {
        private String realmName;
        private Function<Principal, Principal> preRealmRewriter = Function.identity();
        private Function<Principal, Principal> postRealmRewriter = Function.identity();
        private Function<Principal, Principal> finalRewriter = Function.identity();
        private RealmMapper realmMapper;

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        /**
         * Sets a name of the realm to be presented by the mechanism.
         * @param realmName a name of the realm to be presented by the mechanism
         * @return this builder
         */
        public Builder setRealmName(final String realmName) {
            this.realmName = realmName;

            return this;
        }

        /**
         * Set a principal transformer to apply before the realm is selected.
         *
         * @param preRealmRewriter a principal transformer to apply before the realm is selected
         * @return this builder
         */
        public Builder setPreRealmRewriter(final Function<Principal, Principal> preRealmRewriter) {
            Assert.checkNotNullParam("preRealmRewriter", preRealmRewriter);
            this.preRealmRewriter = preRealmRewriter;

            return this;
        }

        /**
         * Set a principal transformer to apply after the realm is selected.  Any previously set credential source will be overwritten.
         *
         * @param postRealmRewriter a principal transformer to apply after the realm is selected
         * @return this builder
         */
        public Builder setPostRealmRewriter(final Function<Principal, Principal> postRealmRewriter) {
            Assert.checkNotNullParam("postRealmRewriter", postRealmRewriter);
            this.postRealmRewriter = postRealmRewriter;

            return this;
        }

        /**
         * Set a final principal transformer to apply for this mechanism realm.  Any previously set credential source will be overwritten.
         *
         * @param finalRewriter a final principal transformer to apply for this mechanism realm
         * @return this builder
         */
        public Builder setFinalRewriter(final Function<Principal, Principal> finalRewriter) {
            Assert.checkNotNullParam("finalRewriter", finalRewriter);
            this.finalRewriter = finalRewriter;

            return this;
        }

        /**
         * Sets a realm mapper to be used by the mechanism.  Any previously set credential source will be overwritten.
         *
         * @param realmMapper a realm mapper to be used by the mechanism
         * @return this builder
         */
        public Builder setRealmMapper(final RealmMapper realmMapper) {
            this.realmMapper = realmMapper;
            return this;
        }

        /**
         * Build a new instance.
         *
         * @return a new instance
         */
        public MechanismRealmConfiguration build() {
            Assert.checkNotNullParam("realmName", realmName);
            return new MechanismRealmConfiguration(realmName, preRealmRewriter, postRealmRewriter, finalRewriter, realmMapper);
        }
    }
}
