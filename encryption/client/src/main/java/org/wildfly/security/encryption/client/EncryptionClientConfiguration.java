/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.encryption.client;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.provider.util.ProviderFactory;

import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Configuration for the Encrypted Expressions client.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

public final class EncryptionClientConfiguration {

    private static final int SET_CREDENTIAL_STORE = 0;
    private static final int ADD_CREDENTIAL_STORE = 1;
    private static final int REMOVE_CREDENTIAL_STORE = 3;
    private static final int SET_RESOLVER = 4;
    private static final int SET_DEFAULT_RESOLVER = 5;
    private static final Supplier<Provider[]> DEFAULT_PROVIDER_SUPPLIER = ProviderFactory.getDefaultProviderSupplier(EncryptionClientConfiguration.class.getClassLoader());

    public static EncryptionClientConfiguration empty() {
        return new EncryptionClientConfiguration();
    }
    Map<String, CredentialStore> credentialStoreMap;
    Map<String, EncryptedExpressionResolver.ResolverConfiguration> resolverMap;
    String defaultResolverName;
    EncryptedExpressionResolver encryptedExpressionResolver;

    EncryptionClientConfiguration() {
        this.credentialStoreMap = new HashMap<>();
        this.resolverMap = new HashMap<>();
        this.defaultResolverName = null;
        this.encryptedExpressionResolver = null;
    }

    @SuppressWarnings("unchecked")
    private EncryptionClientConfiguration(final EncryptionClientConfiguration original, final int what, final Object value) {
         if (what == SET_CREDENTIAL_STORE) {
            if (value == null || ((Map<String, CredentialStore>) value).isEmpty()) {return;}
             setCredentialStoreMap((Map<String, CredentialStore>) value);
        } else if (what == ADD_CREDENTIAL_STORE) {
            if (value == null || ((Map<String, CredentialStore>) value).isEmpty()) {return;}
            Map<String, CredentialStore> newCredentialStorePair = (Map<String, CredentialStore>) value;
            if (this.credentialStoreMap == null) {
                this.credentialStoreMap = new HashMap<>();
            }
            this.credentialStoreMap.putAll(newCredentialStorePair);
        } else if (what == REMOVE_CREDENTIAL_STORE) {
             if (value == null || original.credentialStoreMap == null  || original.credentialStoreMap.isEmpty() || !original.credentialStoreMap.containsKey((String) value)) {return;}
             credentialStoreMap = original.getCredentialStoreMap();
             credentialStoreMap.keySet().remove((String) value);
        } else {
             this.credentialStoreMap = original.credentialStoreMap;
        }
        if (what == SET_RESOLVER) {
            if (value == null || ((EncryptedExpressionResolver) value).getResolverConfiguration().isEmpty()) {return;}
            setResolverMap(((EncryptedExpressionResolver) value).getResolverConfiguration());
            this.encryptedExpressionResolver = ((EncryptedExpressionResolver) value);
        } else {
            this.resolverMap = original.resolverMap;
        }
        if (what == SET_DEFAULT_RESOLVER) {
            this.defaultResolverName = (String) value;
        } else {
            this.defaultResolverName = original.defaultResolverName;
        }
    }

    private EncryptionClientConfiguration(final EncryptionClientConfiguration original, final EncryptionClientConfiguration other) {
        this.credentialStoreMap = other.credentialStoreMap;
        this.resolverMap = other.resolverMap;
        this.defaultResolverName = other.defaultResolverName;
    }

    Map<String, CredentialStore> getCredentialStoreMap() {
        return credentialStoreMap;
    }

    public EncryptionClientConfiguration useCredential(Credential credential) {
        if (credential == null) return this;
        if (getCredentialStoreMap().isEmpty()) {
            return new EncryptionClientConfiguration(this, SET_CREDENTIAL_STORE, IdentityCredentials.NONE.withCredential(credential));
        } else {
            return new EncryptionClientConfiguration(this, ADD_CREDENTIAL_STORE, IdentityCredentials.NONE.withCredential(credential));
        }
    }

    public EncryptedExpressionResolver getEncryptedExpressionResolver() {
        return encryptedExpressionResolver;
    }

    public void setCredentialStoreMap(Map<String, CredentialStore> credentialStoreMap) {
        this.credentialStoreMap = credentialStoreMap;
    }

    public void setResolverMap(Map<String, EncryptedExpressionResolver.ResolverConfiguration> resolverMap) {
        this.resolverMap = resolverMap;
    }

    public Map<String, EncryptedExpressionResolver.ResolverConfiguration> getResolverMap() {
        return resolverMap;
    }

    public void setDefaultResolverName(String defaultResolverName) {
        this.defaultResolverName = defaultResolverName;
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given credential store
     * in addition to existing ones.
     *
     * @param credentialStoreName the name of the credential store to add (must not be {@code null})
     * @param credentialStore the credential store to add (must not be {@code null})
     * @return the new configuration
     */
    public EncryptionClientConfiguration addCredentialStore(String credentialStoreName, CredentialStore credentialStore) {
        Assert.checkNotNullParam("name", credentialStoreName);
        Assert.checkNotNullParam("credentialStore", credentialStore);
        Map<String, CredentialStore> credentialStorePair = new HashMap<>();
        credentialStorePair.put(credentialStoreName, credentialStore);
        EncryptionClientConfiguration config = new EncryptionClientConfiguration(this, ADD_CREDENTIAL_STORE, credentialStorePair);
        return config;
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given credential stores
     * instead of the previous ones.
     *
     * @param credentialStoreMap the map of the credential store to use in place of the current ones (must not be {@code null})
     * @return the new configuration
     */
    public EncryptionClientConfiguration useCredentialStoreMap(Map<String, CredentialStore> credentialStoreMap) {
        if (credentialStoreMap == null || credentialStoreMap.isEmpty()) { return this; }
        return new EncryptionClientConfiguration(this, SET_CREDENTIAL_STORE, credentialStoreMap);
    }

    /**
     * Create a new configuration which is the same as this configuration, but removes the given credential store
     * from the credential store map.
     *
     * @param credentialStoreName the name of the credential store to add (must not be {@code null})
     * @return the new configuration
     */
    public EncryptionClientConfiguration removeCredentialStore(String credentialStoreName) {
        Assert.checkNotNullParam("name", credentialStoreName);
        EncryptionClientConfiguration config = new EncryptionClientConfiguration(this, REMOVE_CREDENTIAL_STORE, credentialStoreName);
        return config;
    }

    /**
     * Create a new configuration which is the same as this configuration, but which uses the given resolver
     * in place of existing one.
     *
     * @param resolver the Encrypted Expression Resolver to add (must not be {@code null})
     * @return the new configuration
     */
    public EncryptionClientConfiguration addEncryptedExpressionResolver(EncryptedExpressionResolver resolver) {
        Assert.checkNotNullParam("encrypted expression resolver", resolver);
        Map<String, EncryptedExpressionResolver.ResolverConfiguration> resolverConfigurationMap = new HashMap<>();
        resolverConfigurationMap.putAll(resolver.getResolverConfiguration());
        EncryptionClientConfiguration config = new EncryptionClientConfiguration(this, SET_RESOLVER, resolver);
        return config;
    }
}
