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

package org.wildfly.security.auth.realm;

import java.security.Principal;
import java.util.Collection;
import java.util.function.Function;

import org.wildfly.common.function.ExceptionConsumer;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.CloseableIterator;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * <p>A wrapper class that provides caching capabilities for a {@link org.wildfly.security.auth.server.ModifiableSecurityRealm} and its identities.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class CachingModifiableSecurityRealm extends CachingSecurityRealm implements ModifiableSecurityRealm {

    /**
     * Creates a new instance.
     *
     * @param realm the {@link SecurityRealm} whose {@link RealmIdentity} should be cached..
     * @param cache the {@link RealmIdentityCache} instance
     */
    public CachingModifiableSecurityRealm(CacheableSecurityRealm realm, RealmIdentityCache cache) {
        super(realm, cache);
    }

    @Override
    public ModifiableRealmIdentity getRealmIdentityForUpdate(Principal principal) throws RealmUnavailableException {
        return wrap(getModifiableSecurityRealm().getRealmIdentityForUpdate(principal));
    }

    @Override
    public CloseableIterator<ModifiableRealmIdentity> getRealmIdentityIterator() throws RealmUnavailableException {
        CloseableIterator<ModifiableRealmIdentity> iterator = getModifiableSecurityRealm().getRealmIdentityIterator();
        return new CloseableIterator<ModifiableRealmIdentity>() {
            @Override
            public boolean hasNext() {
                return iterator.hasNext();
            }

            @Override
            public ModifiableRealmIdentity next() {
                return wrap(iterator.next());
            }
        };
    }

    private ModifiableRealmIdentity wrap(final ModifiableRealmIdentity modifiable) {
        return new ModifiableRealmIdentity() {
            @Override
            public void delete() throws RealmUnavailableException {
                executeAndInvalidate(modifiable -> { modifiable.delete(); });
            }

            @Override
            public void create() throws RealmUnavailableException {
                modifiable.create();
            }

            @Override
            public void setCredentials(Collection<? extends Credential> credentials) throws RealmUnavailableException {
                executeAndInvalidate(modifiable -> { modifiable.setCredentials(credentials); });
            }

            @Override
            public void setAttributes(Attributes attributes) throws RealmUnavailableException {
                executeAndInvalidate(modifiable -> { modifiable.setAttributes(attributes); });
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
                return modifiable.getCredentialAcquireSupport(credentialType, algorithmName);
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                return modifiable.getCredential(credentialType);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return modifiable.getEvidenceVerifySupport(evidenceType, algorithmName);
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                return modifiable.verifyEvidence(evidence);
            }

            @Override
            public boolean exists() throws RealmUnavailableException {
                return modifiable.exists();
            }

            @Override
            public void updateCredential(Credential credential) throws RealmUnavailableException {
                executeAndInvalidate(modifiable -> { modifiable.updateCredential(credential); });
            }

            @Override
            public Principal getRealmIdentityPrincipal() {
                return modifiable.getRealmIdentityPrincipal();
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
                return modifiable.getCredential(credentialType, algorithmName);
            }

            @Override
            public <C extends Credential, R> R applyToCredential(Class<C> credentialType, Function<C, R> function) throws RealmUnavailableException {
                return modifiable.applyToCredential(credentialType, function);
            }

            @Override
            public <C extends Credential, R> R applyToCredential(Class<C> credentialType, String algorithmName, Function<C, R> function) throws RealmUnavailableException {
                return modifiable.applyToCredential(credentialType, algorithmName, function);
            }

            @Override
            public void dispose() {
                modifiable.dispose();
            }

            @Override
            public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                return modifiable.getAuthorizationIdentity();
            }

            @Override
            public Attributes getAttributes() throws RealmUnavailableException {
                return modifiable.getAttributes();
            }

            private void executeAndInvalidate(ExceptionConsumer<ModifiableRealmIdentity, RealmUnavailableException> operation) throws RealmUnavailableException {
                try {
                    operation.accept(modifiable);
                } catch (RealmUnavailableException rue) {
                    throw rue;
                } finally {
                    removeFromCache(modifiable.getRealmIdentityPrincipal());
                }
            }
        };
    }

    private ModifiableSecurityRealm getModifiableSecurityRealm() {
        return (ModifiableSecurityRealm) getCacheableRealm();
    }
}
