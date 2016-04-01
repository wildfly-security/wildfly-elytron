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

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.password.Password;

/**
 * Simple map-backed security realm.  Uses an in-memory copy-on-write map methodology to map user names to
 * entries.  Since this security realm implementation holds all names in memory, it may not be the best choice
 * for very large security realms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleMapBackedSecurityRealm implements SecurityRealm {

    private final NameRewriter rewriter;
    private volatile Map<String, SimpleRealmEntry> map = Collections.emptyMap();

    /**
     * Construct a new instance.
     *
     * @param rewriter the name rewriter to use (cannot be {@code null})
     */
    public SimpleMapBackedSecurityRealm(final NameRewriter rewriter) {
        Assert.checkNotNullParam("rewriter", rewriter);
        this.rewriter = rewriter;
    }

    /**
     * Construct a new instance.
     */
    public SimpleMapBackedSecurityRealm() {
        this(NameRewriter.IDENTITY_REWRITER);
    }

    /**
     * Set the realm entry map.  Note that the entry map must <b>not</b> be modified after calling this method.
     * If it needs to be changed, pass in a new map that is a copy of the old map with the required changes.
     *
     * @param map the password map
     */
    public void setPasswordMap(final Map<String, SimpleRealmEntry> map) {
        Assert.checkNotNullParam("map", map);
        this.map = map;
    }

    /**
     * Set the password map to contain a single entry.
     *
     * @param name the entry name
     * @param password the password
     * @param attributes the identity attributes
     */
    public void setPasswordMap(final String name, final Password password, final Attributes attributes) {
        Assert.checkNotNullParam("name", name);
        Assert.checkNotNullParam("password", password);
        Assert.checkNotNullParam("attributes", attributes);
        map = Collections.singletonMap(name, new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(password)), attributes));
    }

    /**
     * Set the password map to contain a single entry.
     *
     * @param name the entry name
     * @param password the password
     */
    public void setPasswordMap(final String name, final Password password) {
        Assert.checkNotNullParam("name", name);
        Assert.checkNotNullParam("password", password);
        map = Collections.singletonMap(name, new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(password))));
    }

    @Override
    public RealmIdentity getRealmIdentity(String name, final Principal principal, final Evidence evidence) {
        if (name == null) {
            return RealmIdentity.NON_EXISTENT;
        }
        name = rewriter.rewriteName(name);
        if (name == null) {
            throw ElytronMessages.log.invalidName();
        }
        return new SimpleMapRealmIdentity(name);
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
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

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            final SimpleRealmEntry entry = map.get(name);
            if (entry == null) return SupportLevel.UNSUPPORTED;
            for (Credential credential : entry.getCredentials()) {
                if (credentialType.isInstance(credential)) {
                    if (algorithmName == null || credential instanceof AlgorithmCredential && algorithmName.equals(((AlgorithmCredential) credential).getAlgorithm())) {
                        return SupportLevel.SUPPORTED;
                    }
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
            Assert.checkNotNullParam("credentialType", credentialType);
            final SimpleRealmEntry entry = map.get(name);
            if (entry == null) return null;
            for (Credential credential : entry.getCredentials()) {
                if (credentialType.isInstance(credential)) {
                    if (algorithmName == null || credential instanceof AlgorithmCredential && algorithmName.equals(((AlgorithmCredential) credential).getAlgorithm())) {
                        return credentialType.cast(credential);
                    }
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
            for (Credential credential : entry.getCredentials()) {
                if (credential.canVerify(evidence)) {
                    return credential.verify(evidence);
                }
            }
            return false;
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return map.containsKey(name);
        }

        public boolean createdBySecurityRealm(final SecurityRealm securityRealm) {
            return SimpleMapBackedSecurityRealm.this == securityRealm;
        }
    }
}
