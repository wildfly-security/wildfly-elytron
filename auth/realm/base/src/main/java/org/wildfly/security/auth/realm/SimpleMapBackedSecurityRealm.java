/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.realm;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.security.Principal;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.password.Password;

import static org.wildfly.security.auth.realm.ElytronMessages.log;

/**
 * Simple map-backed security realm.  Uses an in-memory copy-on-write map methodology to map user names to
 * entries.  Since this security realm implementation holds all names in memory, it may not be the best choice
 * for very large security realms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleMapBackedSecurityRealm implements SecurityRealm {

    private final Supplier<Provider[]> providers;
    private final NameRewriter rewriter;
    private volatile Map<String, SimpleRealmEntry> map = Collections.emptyMap();

    /**
     * Construct a new instance.
     *
     * @param rewriter the name rewriter to use (cannot be {@code null})
     */
    public SimpleMapBackedSecurityRealm(final NameRewriter rewriter) {
        this(rewriter, INSTALLED_PROVIDERS);
    }

    /**
     * Construct a new instance.
     *
     * @param rewriter the name rewriter to use (cannot be {@code null})
     * @param providers a supplier of providers for use by this realm (cannot be {@code null})
     */
    public SimpleMapBackedSecurityRealm(final NameRewriter rewriter, final Supplier<Provider[]> providers) {
        this.rewriter = checkNotNullParam("rewriter", rewriter);
        this.providers = checkNotNullParam("provider", providers);
    }

    /**
     * Construct a new instance.
     */
    public SimpleMapBackedSecurityRealm() {
        this(NameRewriter.IDENTITY_REWRITER);
    }

    /**
     * Construct a new instance.
     *
     * @param providers a supplier of providers for use by this realm (cannot be {@code null})
     */
    public SimpleMapBackedSecurityRealm(final Supplier<Provider[]> providers) {
        this(NameRewriter.IDENTITY_REWRITER, providers);
    }

    /**
     * Set the realm identity map.  Note that the entry map must <b>not</b> be modified after calling this method.
     * If it needs to be changed, pass in a new map that is a copy of the old map with the required changes.
     *
     * @param map the identity map where key is an identity name and value is an identity entry
     */
    public void setIdentityMap(final Map<String, SimpleRealmEntry> map) {
        Assert.checkNotNullParam("map", map);
        this.map = map;
    }

    /**
     * Set the realm identity map.  Note that the entry map must <b>not</b> be modified after calling this method.
     * If it needs to be changed, pass in a new map that is a copy of the old map with the required changes.
     *
     * @param map the identity map
     * @deprecated Use {@link #setIdentityMap(Map)} instead.
     */
    @Deprecated
    public void setPasswordMap(final Map<String, SimpleRealmEntry> map) {
        setIdentityMap(map);
    }

    /**
     * Set the realm identity map to contain a single entry.
     *
     * @param name the entry name
     * @param password the password
     * @param attributes the identity attributes
     * @deprecated Use {@link #setIdentityMap(Map)} instead.
     */
    @Deprecated
    public void setPasswordMap(final String name, final Password password, final Attributes attributes) {
        setIdentityMap(Collections.singletonMap(name, new SimpleRealmEntry(
                Collections.singletonList(new PasswordCredential(password)),
                attributes
        )));
    }

    /**
     * Set the realm identity map to contain a single entry.
     *
     * @param name the entry name
     * @param password the password
     * @deprecated Use {@link #setIdentityMap(Map)} instead.
     */
    @Deprecated
    public void setPasswordMap(final String name, final Password password) {
        setPasswordMap(name, password, Attributes.EMPTY);
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) {
        if (! NamePrincipal.isConvertibleTo(principal)) {
            return RealmIdentity.NON_EXISTENT;
        }
        String name = rewriter.rewriteName(principal.getName());
        if (name == null) {
            throw log.invalidName();
        }
        return new SimpleMapRealmIdentity(name);
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidenceType", evidenceType);
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    private class SimpleMapRealmIdentity implements RealmIdentity {

        private final String name;

        SimpleMapRealmIdentity(final String name) {
            this.name = name;
        }

        public Principal getRealmIdentityPrincipal() {
            return new NamePrincipal(name);
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            final SimpleRealmEntry entry = map.get(name);
            if (entry == null) return SupportLevel.UNSUPPORTED;
            for (Credential credential : entry.getCredentials()) {
                if (credential.matches(credentialType, algorithmName, parameterSpec)) {
                    return SupportLevel.SUPPORTED;
                }
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return getCredential(credentialType, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return getCredential(credentialType, algorithmName, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            checkNotNullParam("credentialType", credentialType);
            final SimpleRealmEntry entry = map.get(name);
            if (entry == null) return null;
            for (Credential credential : entry.getCredentials()) {
                if (credential.matches(credentialType, algorithmName, parameterSpec)) {
                    return credentialType.cast(credential.clone());
                }
            }
            return null;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() {
            final SimpleRealmEntry entry = map.get(name);
            return entry == null ? AuthorizationIdentity.EMPTY : AuthorizationIdentity.basicIdentity(entry.getAttributes());
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            SimpleRealmEntry entry = map.get(name);
            if (entry == null) {
                return SupportLevel.UNSUPPORTED;
            }
            for (Credential credential : entry.getCredentials()) {
                if (credential.canVerify(evidenceType, algorithmName)) {
                    return SupportLevel.SUPPORTED;
                }
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            SimpleRealmEntry entry = map.get(name);
            if (entry == null) {
                return false;
            }

            log.tracef("Trying to authenticate %s using SimpleMapBackedSecurityRealm.", name);

            for (Credential credential : entry.getCredentials()) {
                if (credential.canVerify(evidence)) {
                    return credential.verify(providers, evidence);
                }
            }
            return false;
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return map.containsKey(name);
        }
    }
}
