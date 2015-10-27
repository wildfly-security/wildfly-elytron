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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.wildfly.common.Assert;

/**
 * A configuration that applies to an authentication mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MechanismConfiguration {
    private final NameRewriter preRealmRewriter;
    private final NameRewriter postRealmRewriter;
    private final NameRewriter finalRewriter;
    private final Supplier<List<String>> credentialNameSupplier;
    private final Map<String, MechanismRealmConfiguration> mechanismRealms;

    MechanismConfiguration(final NameRewriter preRealmRewriter, final NameRewriter postRealmRewriter, final NameRewriter finalRewriter, final Supplier<List<String>> credentialNameSupplier, final Collection<MechanismRealmConfiguration> mechanismRealms) {
        Assert.checkNotNullParam("preRealmRewriter", preRealmRewriter);
        Assert.checkNotNullParam("postRealmRewriter", postRealmRewriter);
        Assert.checkNotNullParam("finalRewriter", finalRewriter);
        Assert.checkNotNullParam("credentialNameSupplier", credentialNameSupplier);
        Assert.checkNotNullParam("mechanismRealms", mechanismRealms);
        this.preRealmRewriter = preRealmRewriter;
        this.postRealmRewriter = postRealmRewriter;
        this.finalRewriter = finalRewriter;
        this.credentialNameSupplier = credentialNameSupplier;
        final Iterator<MechanismRealmConfiguration> iterator = mechanismRealms.iterator();
        if (! iterator.hasNext()) {
            // zero
            this.mechanismRealms = Collections.emptyMap();
        } else {
            MechanismRealmConfiguration item = iterator.next();
            if (! iterator.hasNext()) {
                // one
                this.mechanismRealms = Collections.singletonMap(item.getRealmName(), item);
            } else {
                // two or more
                Map<String, MechanismRealmConfiguration> map = new LinkedHashMap<>(mechanismRealms.size());
                map.put(item.getRealmName(), item);
                do {
                    item = iterator.next();
                    map.put(item.getRealmName(), item);
                } while (iterator.hasNext());
                this.mechanismRealms = Collections.unmodifiableMap(map);
            }
        }
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
     * Get the credential name supplier, if any.
     *
     * @return the credential name supplier, or {@code null} if none is configured
     */
    public Supplier<List<String>> getCredentialNameSupplier() {
        return credentialNameSupplier;
    }

    /**
     * Get the collection of mechanism realm names, in order.  If no realms are configured, the collection will be
     * empty.
     *
     * @return the mechanism realm names to offer (may be empty; not {@code null})
     */
    public Collection<String> getMechanismRealmNames() {
        return mechanismRealms.keySet();
    }

    /**
     * Get the mechanism realm configuration for the offered realm with the given name.  If the realm name is not known,
     * {@code null} is returned.  If the realm name is equal to one of the names returned by {@link #getMechanismRealmNames()}
     * on this same instance then it is guaranteed that {@code null} is never returned.
     *
     * @param realmName the realm name
     * @return the realm configuration, or {@code null} if the realm name is unknown
     */
    public MechanismRealmConfiguration getMechanismRealmConfiguration(String realmName) {
        return mechanismRealms.get(realmName);
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link MechanismConfiguration}.
     *
     * @return a new {@link Builder} capable of building a {@link MechanismConfiguration}.
     */
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private NameRewriter preRealmRewriter = NameRewriter.IDENTITY_REWRITER;
        private NameRewriter postRealmRewriter = NameRewriter.IDENTITY_REWRITER;
        private NameRewriter finalRewriter = NameRewriter.IDENTITY_REWRITER;
        private Supplier<List<String>> credentialNameSupplier = () -> Collections.singletonList("clear-password");
        private List<MechanismRealmConfiguration> mechanismRealms;

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        public Builder setPreRealmRewriter(final NameRewriter preRealmRewriter) {
            Assert.checkNotNullParam("preRealmRewriter", preRealmRewriter);
            this.preRealmRewriter = preRealmRewriter;
            return this;
        }

        public Builder setPostRealmRewriter(final NameRewriter postRealmRewriter) {
            Assert.checkNotNullParam("postRealmRewriter", postRealmRewriter);
            this.postRealmRewriter = postRealmRewriter;
            return this;
        }

        public Builder setFinalRewriter(final NameRewriter finalRewriter) {
            Assert.checkNotNullParam("finalRewriter", finalRewriter);
            this.finalRewriter = finalRewriter;
            return this;
        }

        public Builder setCredentialNameSupplier(final Supplier<List<String>> credentialNameSupplier) {
            Assert.checkNotNullParam("credentialNameSupplier", credentialNameSupplier);
            this.credentialNameSupplier = credentialNameSupplier;
            return this;
        }

        public Builder addMechanismRealm(MechanismRealmConfiguration configuration) {
            Assert.checkNotNullParam("configuration", configuration);
            List<MechanismRealmConfiguration> mechanismRealms = this.mechanismRealms;
            if (mechanismRealms == null) {
                mechanismRealms = this.mechanismRealms = new ArrayList<>();
            }
            mechanismRealms.add(configuration);
            return this;
        }

        /**
         * Build a new instance.  If no mechanism realms are offered, an empty collection should be provided for
         * {@code mechanismRealms}; otherwise, if the mechanism only supports one realm, the first will be used.  If the
         * mechanism does not support realms, {@code mechanismRealms} is ignored.
         */
        public MechanismConfiguration build() {
            final List<MechanismRealmConfiguration> mechanismRealms = this.mechanismRealms;
            return new MechanismConfiguration(preRealmRewriter, postRealmRewriter, finalRewriter, credentialNameSupplier, mechanismRealms == null ? Collections.emptyList() : mechanismRealms);
        }
    }

    /**
     * An empty mechanism configuration which always attempts to authenticate against a credential called {@code clear-password}.
     */
    public static final MechanismConfiguration EMPTY = new MechanismConfiguration(NameRewriter.IDENTITY_REWRITER, NameRewriter.IDENTITY_REWRITER, NameRewriter.IDENTITY_REWRITER, () -> Collections.singletonList("clear-password"), Collections.emptyList());
}
