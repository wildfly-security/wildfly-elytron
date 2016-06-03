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

import static org.wildfly.common.Assert.assertNotNull;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.wildfly.common.Assert;
import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.credential.Credential;

/**
 * A configuration that applies to an authentication mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MechanismConfiguration {

    private final MechanismConfiguration parent;
    private final NameRewriter preRealmRewriter;
    private final NameRewriter postRealmRewriter;
    private final NameRewriter finalRewriter;
    private final RealmMapper realmMapper;
    private final Map<String, MechanismRealmConfiguration> mechanismRealms;
    private final SecurityFactory<Credential> serverCredentialFactory;
    private final Map<String, MechanismConfiguration> serverSpecificConfiguration;

    MechanismConfiguration(final MechanismConfiguration parent, final NameRewriter preRealmRewriter, final NameRewriter postRealmRewriter, final NameRewriter finalRewriter, final RealmMapper realmMapper, final Collection<MechanismRealmConfiguration> mechanismRealms, final SecurityFactory<Credential> serverCredentialFactory) {
        this.parent = parent;
        serverSpecificConfiguration = parent == null ? new HashMap<>() : null;
        Assert.checkNotNullParam("mechanismRealms", mechanismRealms);
        this.serverCredentialFactory = serverCredentialFactory;
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
    }

    void addServerConfiguration(final String serverName, final MechanismConfiguration serverConfiguration) {
        assertNotNull(serverSpecificConfiguration);
        serverSpecificConfiguration.put(serverName, serverConfiguration);
    }

    /**
     * Obtain the server specific {@code MechanismConfiguration}, if no server specific configuration is set the default is returned instead.
     *
     * @param serverName the name of the server the specific configuration is required for.
     * @return the server specific {@code MechanismConfiguration}, if no server specific configuration is set the default is returned instead.
     */
    public MechanismConfiguration forServer(final String serverName) {
        if (parent != null) {
            return parent.forServer(serverName);
        }

        assertNotNull(serverSpecificConfiguration);
        MechanismConfiguration result = serverSpecificConfiguration.get(serverName);

        return result != null ? result : this;
    }

    /**
     * Get the pre-realm rewriter for this mechanism realm.
     *
     * @return the pre-realm rewriter for this mechanism realm, or {@code null} to use the default
     */
    public NameRewriter getPreRealmRewriter() {
        return preRealmRewriter;
    }

    /**
     * Get the post-realm rewriter for this mechanism realm.
     *
     * @return the post-realm rewriter for this mechanism realm, or {@code null} to use the default
     */
    public NameRewriter getPostRealmRewriter() {
        return postRealmRewriter;
    }

    /**
     * Get the final rewriter for this mechanism realm.
     *
     * @return the final rewriter for this mechanism realm, or {@code null} to use the default
     */
    public NameRewriter getFinalRewriter() {
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

    public abstract static class AbstractBuilder<T, R> {

        private static final MechanismRealmConfiguration[] NO_REALM_CONFIGS = new MechanismRealmConfiguration[0];

        private NameRewriter preRealmRewriter;
        private NameRewriter postRealmRewriter;
        private NameRewriter finalRewriter;
        private RealmMapper realmMapper;
        private List<MechanismRealmConfiguration> mechanismRealms;
        private SecurityFactory<Credential> serverCredentialFactory;

        /**
         * Construct a new instance.
         */
        AbstractBuilder() {
        }

        public T setPreRealmRewriter(final NameRewriter preRealmRewriter) {
            this.preRealmRewriter = preRealmRewriter;
            return getThis();
        }

        public T setPostRealmRewriter(final NameRewriter postRealmRewriter) {
            this.postRealmRewriter = postRealmRewriter;
            return getThis();
        }

        public T setFinalRewriter(final NameRewriter finalRewriter) {
            this.finalRewriter = finalRewriter;
            return getThis();
        }

        public T setRealmMapper(final RealmMapper realmMapper) {
            this.realmMapper = realmMapper;
            return getThis();
        }

        public T addMechanismRealm(MechanismRealmConfiguration configuration) {
            Assert.checkNotNullParam("configuration", configuration);
            List<MechanismRealmConfiguration> mechanismRealms = this.mechanismRealms;
            if (mechanismRealms == null) {
                mechanismRealms = this.mechanismRealms = new ArrayList<>(1);
            }
            mechanismRealms.add(configuration);
            return getThis();
        }

        /**
         * Set the server credential.
         *
         * @param credential the credential to set (must not be {@code null})
         * @return this builder
         */
        public T setServerCredential(Credential credential) {
            this.serverCredentialFactory = new FixedSecurityFactory<Credential>(Assert.checkNotNullParam("credential", credential));

            return getThis();
        }

        /**
         * Set the server credential factory.
         *
         * @param credentialFactory the credential factory to add (must not be {@code null})
         * @return this builder
         */
        public T setServerCredential(SecurityFactory<Credential> credentialFactory) {
            this.serverCredentialFactory = Assert.checkNotNullParam("credentialFactory", credentialFactory);

            return getThis();
        }

        protected MechanismConfiguration build(MechanismConfiguration parent) {
            List<MechanismRealmConfiguration> mechanismRealms = this.mechanismRealms;
            if (mechanismRealms == null) {
                mechanismRealms = emptyList();
            } else {
                mechanismRealms = unmodifiableList(asList(mechanismRealms.toArray(NO_REALM_CONFIGS)));
            }
            return new MechanismConfiguration(parent, preRealmRewriter, postRealmRewriter, finalRewriter, realmMapper, mechanismRealms, serverCredentialFactory);
        }

        public abstract R build();

        protected abstract T getThis();

    }

    public static final class Builder extends AbstractBuilder<Builder, MechanismConfiguration> {

        private final List<ServerBuilder> serverBuilders = new ArrayList<>();

        /**
         * Create a new {@code Builder} for a named server.
         *
         * This method should only be called once for each unique server name.
         *
         * @param serverName the name of the server the configuration is being built for.
         * @return a new {@code Builder} for a named server.
         */
        public ServerBuilder forServer(String serverName) {
            ServerBuilder serverBuilder = new ServerBuilder(serverName, this);
            serverBuilders.add(serverBuilder);

            return serverBuilder;
        }

        /**
         * Build a new instance.  If no mechanism realms are offered, an empty collection should be provided for
         * {@code mechanismRealms}; otherwise, if the mechanism only supports one realm, the first will be used.  If the
         * mechanism does not support realms, {@code mechanismRealms} is ignored.
         */
        public MechanismConfiguration build() {
            final MechanismConfiguration parentConfiguration = super.build(null);
            serverBuilders.forEach((sb) -> sb.buildServerConfiguration(parentConfiguration));

            return parentConfiguration;
        }

        @Override
        protected Builder getThis() {
            return this;
        }
    }

    public static final class ServerBuilder extends AbstractBuilder<ServerBuilder, Builder> {

        private final String serverName;
        private final Builder parent;

        ServerBuilder(String serverName, Builder parent) {
            this.serverName = serverName;
            this.parent = parent;
        }

        void buildServerConfiguration(MechanismConfiguration parent) {
            MechanismConfiguration serverConfiguration = super.build(parent);
            parent.addServerConfiguration(serverName, serverConfiguration);
        }

        /**
         * Finish building this server specific configuration and obtain a reference back to the parent {@code Builder}.
         *
         * @return a reference to the parent {@code Builder}
         */
        @Override
        public Builder build() {
            return parent;
        }

        @Override
        protected ServerBuilder getThis() {
            return this;
        }

    }

    /**
     * An empty mechanism configuration..
     */
    public static final MechanismConfiguration EMPTY = new MechanismConfiguration(null, null, null, null, null, emptyList(), null);
}
