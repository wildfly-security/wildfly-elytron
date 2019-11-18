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

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static org.wildfly.common.Assert.checkNotNullParam;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.source.CredentialSource;

/**
 * A configuration that applies to an authentication mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MechanismConfiguration {
    private final Function<Principal, Principal> preRealmRewriter;
    private final Function<Principal, Principal> postRealmRewriter;
    private final Function<Principal, Principal> finalRewriter;
    private final RealmMapper realmMapper;
    private final Map<String, MechanismRealmConfiguration> mechanismRealms;
    private final CredentialSource serverCredentialSource;

    MechanismConfiguration(final Function<Principal, Principal> preRealmRewriter, final Function<Principal, Principal> postRealmRewriter, final Function<Principal, Principal> finalRewriter, final RealmMapper realmMapper, final Collection<MechanismRealmConfiguration> mechanismRealms, final CredentialSource serverCredentialSource) {
        checkNotNullParam("mechanismRealms", mechanismRealms);
        this.preRealmRewriter = preRealmRewriter;
        this.postRealmRewriter = postRealmRewriter;
        this.finalRewriter = finalRewriter;
        this.realmMapper = realmMapper;
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
        this.serverCredentialSource = serverCredentialSource;
    }

    /**
     * Get the pre-realm rewriter for this mechanism realm.
     *
     * @return the pre-realm rewriter for this mechanism realm, or {@code null} to use the default
     */
    public Function<Principal, Principal> getPreRealmRewriter() {
        return preRealmRewriter;
    }

    /**
     * Get the post-realm rewriter for this mechanism realm.
     *
     * @return the post-realm rewriter for this mechanism realm, or {@code null} to use the default
     */
    public Function<Principal, Principal> getPostRealmRewriter() {
        return postRealmRewriter;
    }

    /**
     * Get the final rewriter for this mechanism realm.
     *
     * @return the final rewriter for this mechanism realm, or {@code null} to use the default
     */
    public Function<Principal, Principal> getFinalRewriter() {
        return finalRewriter;
    }

    /**
     * Get the realm mapper.
     *
     * @return the realm mapper, or {@code null} to use the default
     */
    public RealmMapper getRealmMapper() {
        return realmMapper;
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
     * Get the server credential source.
     *
     * @return the server credential source
     */
    public CredentialSource getServerCredentialSource() {
        return serverCredentialSource;
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

    /**
     * A builder for authentication mechanism configuration.
     */
    public static final class Builder {
        private static final MechanismRealmConfiguration[] NO_REALM_CONFIGS = new MechanismRealmConfiguration[0];

        private Function<Principal, Principal> preRealmRewriter = Function.identity();
        private Function<Principal, Principal> postRealmRewriter = Function.identity();
        private Function<Principal, Principal> finalRewriter = Function.identity();
        private RealmMapper realmMapper;
        private List<MechanismRealmConfiguration> mechanismRealms;
        private CredentialSource serverCredentialSource = CredentialSource.NONE;

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        /**
         * Set a principal transformer to apply before the realm is selected.
         *
         * @param preRealmRewriter a principal transformer to apply before the realm is selected
         * @return this builder
         */
        public Builder setPreRealmRewriter(final Function<Principal, Principal> preRealmRewriter) {
            checkNotNullParam("preRealmRewriter", preRealmRewriter);
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
            checkNotNullParam("postRealmRewriter", postRealmRewriter);
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
            checkNotNullParam("finalRewriter", finalRewriter);
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
         * Adds a configuration for one of realms of this mechanism.
         *
         * @param configuration a configuration for one of realms of this mechanism
         * @return this builder
         */
        public Builder addMechanismRealm(MechanismRealmConfiguration configuration) {
            checkNotNullParam("configuration", configuration);
            List<MechanismRealmConfiguration> mechanismRealms = this.mechanismRealms;
            if (mechanismRealms == null) {
                mechanismRealms = this.mechanismRealms = new ArrayList<>(1);
            }
            mechanismRealms.add(configuration);
            return this;
        }

        /**
         * Set a single server credential.  Any previously set credential source will be overwritten.
         *
         * @param credential the credential to set (must not be {@code null})
         * @return this builder
         */
        public Builder setServerCredential(Credential credential) {
            checkNotNullParam("credential", credential);
            return setServerCredentialSource(IdentityCredentials.NONE.withCredential(credential));
        }

        /**
         * Set a single server credential factory.  Any previously set credential source will be overwritten.
         *
         * @param credentialFactory the credential factory to set (must not be {@code null})
         * @return this builder
         */
        public Builder setServerCredential(SecurityFactory<? extends Credential> credentialFactory) {
            checkNotNullParam("credential", credentialFactory);
            return setServerCredentialSource(CredentialSource.fromSecurityFactory(credentialFactory));
        }

        /**
         * Set the server credential source.  Any previously set credential source will be overwritten.
         *
         * @param serverCredentialSource the server credential source (must not be {@code null})
         * @return this builder
         */
        public Builder setServerCredentialSource(final CredentialSource serverCredentialSource) {
            checkNotNullParam("serverCredentialSource", serverCredentialSource);
            this.serverCredentialSource = serverCredentialSource;
            return this;
        }

        /**
         * Build a new instance.  If no mechanism realms are offered, an empty collection should be provided for
         * {@code mechanismRealms}; otherwise, if the mechanism only supports one realm, the first will be used.  If the
         * mechanism does not support realms, {@code mechanismRealms} is ignored.
         *
         * @return a new instance
         */
        public MechanismConfiguration build() {
            List<MechanismRealmConfiguration> mechanismRealms = this.mechanismRealms;
            if (mechanismRealms == null) {
                mechanismRealms = emptyList();
            } else {
                mechanismRealms = unmodifiableList(asList(mechanismRealms.toArray(NO_REALM_CONFIGS)));
            }
            return new MechanismConfiguration(preRealmRewriter, postRealmRewriter, finalRewriter, realmMapper, mechanismRealms, serverCredentialSource);
        }
    }

    /**
     * An empty mechanism configuration..
     */
    public static final MechanismConfiguration EMPTY = new MechanismConfiguration(Function.identity(), Function.identity(), Function.identity(), null, emptyList(), CredentialSource.NONE);
}
