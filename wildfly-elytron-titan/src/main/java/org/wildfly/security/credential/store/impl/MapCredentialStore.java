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

package org.wildfly.security.credential.store.impl;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;

/**
 * A map-backed credential store implementation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MapCredentialStore extends CredentialStoreSpi {
    public static final String MAP_CREDENTIAL_STORE = "MapCredentialStore";
    private final Map<String, CredentialSource> credentialSources;
    private final boolean modifiable;

    /**
     * Construct a new instance.
     *
     * @param credentialSources the credential sources map to use as the backing map for this store (must not be {@code null})
     * @param modifiable {@code true} to allow modifications via the API, {@code false} otherwise
     */
    public MapCredentialStore(final ConcurrentMap<String, CredentialSource> credentialSources, final boolean modifiable) {
        this.credentialSources = credentialSources;
        this.modifiable = modifiable;
    }

    /**
     * Construct a new unmodifiable instance.
     *
     * @param credentialSources the credential sources map to use (must not be {@code null})
     */
    public MapCredentialStore(final Map<String, CredentialSource> credentialSources) {
        this.credentialSources = credentialSources;
        this.modifiable = false;
    }

    /**
     * Construct a new, modifiable instance backed by a new concurrent map.
     */
    public MapCredentialStore() {
        this(new ConcurrentHashMap<String, CredentialSource>(), true);
    }

    public void initialize(final Map<String, String> attributes, final CredentialStore.ProtectionParameter protectionParameter, Provider[] providers) throws CredentialStoreException {
        if (protectionParameter != null) {
            throw log.invalidProtectionParameter(protectionParameter);
        }
        // no operation
    }

    public boolean isModifiable() {
        return modifiable;
    }

    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        return new HashSet<>(credentialSources.keySet());
    }

    public boolean exists(final String credentialAlias, final Class<? extends Credential> credentialType) throws CredentialStoreException {
        try {
            return credentialSources.getOrDefault(credentialAlias, CredentialSource.NONE).getCredentialAcquireSupport(credentialType).mayBeSupported();
        } catch (IOException e) {
            throw log.cannotAcquireCredentialFromStore(e);
        }
    }

    public void store(final String credentialAlias, final Credential credential, final CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (isModifiable()) {
            credentialSources.compute(credentialAlias, (alias, old) -> {
                if (old instanceof IdentityCredentials) {
                    return ((IdentityCredentials) old).withCredential(credential);
                }
                final IdentityCredentials newVal = IdentityCredentials.NONE.withCredential(credential);
                if (old == null) {
                    return newVal;
                } else {
                    return old.with(newVal);
                }
            });
        } else {
            throw log.nonModifiableCredentialStore("store");
        }
    }

    public <C extends Credential> C retrieve(final String credentialAlias, final Class<C> credentialType, final String credentialAlgorithm, final AlgorithmParameterSpec parameterSpec, final CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        try {
            return credentialSources.getOrDefault(credentialAlias, CredentialSource.NONE).getCredential(credentialType, credentialAlgorithm, parameterSpec);
        } catch (IOException e) {
            throw log.cannotAcquireCredentialFromStore(e);
        }
    }

    public void remove(final String credentialAlias, final Class<? extends Credential> credentialType, final String credentialAlgorithm, final AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        if (isModifiable()) {
            credentialSources.computeIfPresent(credentialAlias, (alias, old) -> old.without(credentialType, credentialAlgorithm, parameterSpec));
        } else {
            throw log.nonModifiableCredentialStore("remove");
        }
    }
}
