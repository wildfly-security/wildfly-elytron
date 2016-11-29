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

import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.credential.Credential;

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
    private final SecurityFactory<Credential> serverCredentialFactory;

    MechanismConfiguration(final Function<Principal, Principal> preRealmRewriter, final Function<Principal, Principal> postRealmRewriter, final Function<Principal, Principal> finalRewriter, final RealmMapper realmMapper, final Collection<MechanismRealmConfiguration> mechanismRealms, final SecurityFactory<Credential> serverCredentialFactory) {
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
        this.serverCredentialFactory = serverCredentialFactory;
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
     * Get the server credential factory.
     *
     * @return the server credential factory.
     */
    public SecurityFactory<Credential> getServerCredentialFactory() {
        return serverCredentialFactory;
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
        private static final MechanismRealmConfiguration[] NO_REALM_CONFIGS = new MechanismRealmConfiguration[0];

        private Function<Principal, Principal> preRealmRewriter = Function.identity();
        private Function<Principal, Principal> postRealmRewriter = Function.identity();
        private Function<Principal, Principal> finalRewriter = Function.identity();
        private RealmMapper realmMapper;
        private List<MechanismRealmConfiguration> mechanismRealms;
        private SecurityFactory<Credential> serverCredentialFactory;

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        public Builder setPreRealmRewriter(final Function<Principal, Principal> preRealmRewriter) {
            checkNotNullParam("preRealmRewriter", preRealmRewriter);
            this.preRealmRewriter = preRealmRewriter;
            return this;
        }

        public Builder setPostRealmRewriter(final Function<Principal, Principal> postRealmRewriter) {
            checkNotNullParam("postRealmRewriter", postRealmRewriter);
            this.postRealmRewriter = postRealmRewriter;
            return this;
        }

        public Builder setFinalRewriter(final Function<Principal, Principal> finalRewriter) {
            checkNotNullParam("finalRewriter", finalRewriter);
            this.finalRewriter = finalRewriter;
            return this;
        }

        public Builder setRealmMapper(final RealmMapper realmMapper) {
            this.realmMapper = realmMapper;
            return this;
        }

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
         * Set the server credential.
         *
         * @param credential the credential to set (must not be {@code null})
         * @return this builder
         */
        public Builder setServerCredential(Credential credential) {
            checkNotNullParam("credential", credential);
            this.serverCredentialFactory = new FixedSecurityFactory<>(credential);
            return this;
        }

        /**
         * Set the server credential factory.
         *
         * @param credentialFactory the credential factory to set (must not be {@code null})
         * @return this builder
         */
        public Builder setServerCredential(SecurityFactory<Credential> credentialFactory) {
            checkNotNullParam("credential", credentialFactory);
            this.serverCredentialFactory = credentialFactory;
            return this;
        }

        /**
         * Build a new instance.  If no mechanism realms are offered, an empty collection should be provided for
         * {@code mechanismRealms}; otherwise, if the mechanism only supports one realm, the first will be used.  If the
         * mechanism does not support realms, {@code mechanismRealms} is ignored.
         */
        public MechanismConfiguration build() {
            List<MechanismRealmConfiguration> mechanismRealms = this.mechanismRealms;
            if (mechanismRealms == null) {
                mechanismRealms = emptyList();
            } else {
                mechanismRealms = unmodifiableList(asList(mechanismRealms.toArray(NO_REALM_CONFIGS)));
            }
            return new MechanismConfiguration(preRealmRewriter, postRealmRewriter, finalRewriter, realmMapper, mechanismRealms, serverCredentialFactory);
        }
    }

    /**
     * An empty mechanism configuration..
     */
    public static final MechanismConfiguration EMPTY = new MechanismConfiguration(Function.identity(), Function.identity(), Function.identity(), null, emptyList(), null);
}
