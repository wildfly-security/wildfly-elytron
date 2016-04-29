/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.evidence.Evidence;

/**
 * A locator for an identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class IdentityLocator {
    private final String name;
    private final Principal principal;
    private final Evidence evidence;

    IdentityLocator(final String name, final Principal principal, final Evidence evidence) {
        this.name = name;
        this.principal = principal;
        this.evidence = evidence;
    }

    /**
     * Get the identity name.
     *
     * @return the identity name (not {@code null})
     * @throws IllegalStateException if the name field is not set
     */
    public String getName() {
        final String name = this.name;
        if (name == null) throw log.locatorFieldNotSet("name");
        return name;
    }

    /**
     * Determine whether a name is set.
     *
     * @return {@code true} if a name is set, {@code false} otherwise
     */
    public boolean hasName() {
        return name != null;
    }

    /**
     * Get the identity principal.
     *
     * @return the identity principal (not {@code null})
     * @throws IllegalStateException if the principal field is not set
     */
    public Principal getPrincipal() {
        final Principal principal = this.principal;
        if (principal == null) throw log.locatorFieldNotSet("principal");
        return principal;
    }

    /**
     * Determine whether a principal is set.
     *
     * @return {@code true} if a principal is set, {@code false} otherwise
     */
    public boolean hasPrincipal() {
        return principal != null;
    }

    /**
     * Get the identity evidence.
     *
     * @return the identity evidence (not {@code null})
     * @throws IllegalStateException if the evidence field is not set
     */
    public Evidence getEvidence() {
        final Evidence evidence = this.evidence;
        if (evidence == null) throw log.locatorFieldNotSet("evidence");
        return evidence;
    }

    /**
     * Determine whether evidence is set.
     *
     * @return {@code true} if evidence is set, {@code false} otherwise
     */
    public boolean hasEvidence() {
        return evidence != null;
    }

    /**
     * Shortcut method to construct an identity locator from just a name.
     *
     * @param name the name (must not be {@code null})
     * @return the identity locator (not {@code null})
     */
    public static IdentityLocator fromName(String name) {
        Assert.checkNotNullParam("name", name);
        return new IdentityLocator(name, null, null);
    }

    /**
     * A class for building {@link IdentityLocator} instances.
     */
    public static class Builder {
        private String name;
        private Principal principal;
        private Evidence evidence;

        /**
         * Construct a new, empty instance.
         */
        public Builder() {
        }

        /**
         * Set the identity name.
         *
         * @param name the identity name
         */
        public Builder setName(final String name) {
            this.name = name;
            return this;
        }

        /**
         * Set the identity principal.
         *
         * @param principal the identity principal
         */
        public Builder setPrincipal(final Principal principal) {
            this.principal = principal;
            return this;
        }

        /**
         * Set the identity evidence.
         *
         * @param evidence the identity evidence
         */
        public Builder setEvidence(final Evidence evidence) {
            this.evidence = evidence;
            return this;
        }

        /**
         * Determine whether this builder would produce an empty locator.
         *
         * @return {@code true} if empty, {@code false} otherwise
         */
        public boolean isEmpty() {
            return name == null && principal == null && evidence == null;
        }

        /**
         * Build a locator from this builder.
         *
         * @return the new locator (not {@code null})
         */
        public IdentityLocator build() {
            return new IdentityLocator(name, principal, evidence);
        }
    }
}
