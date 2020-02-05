/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.auth.client;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.client._private.ElytronMessages.xmlLog;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.Map;
import java.util.function.Supplier;

import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.XMLLocation;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;

/**
 * Factory which can create instance of {@link CredentialStore} from supplied information.
 * It initializes the instance.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
final class CredentialStoreFactory implements ExceptionSupplier<CredentialStore, ConfigXMLParseException> {

    private final String name;
    private final String type;
    private final Map<String, String> attributes;
    private final XMLLocation location;
    private final ExceptionSupplier<CredentialSource, ConfigXMLParseException> credentialSource;
    private final String providerName;
    private final Supplier<Provider[]> providers;

    /**
     * Creates a factory using parameters.
     *
     * @param name the non {@code null} name of the {@link CredentialStore}
     * @param type the possibly {@code null} type of the {@link CredentialStore}
     * @param attributes the non {@code null} attributes to initialise the {@code CredentialStore}
     * @param providerName the possibly {@code null} name of the provider to use
     * @param location the non {@code null} current parse location
     * @param supplier the possibly {@code null} credential source to unlock the store
     * @param providers the possibly {@code null} supplier of provider instances to search and use to create the store
     */
    CredentialStoreFactory(String name, String type, Map<String, String> attributes, String providerName, XMLLocation location, ExceptionSupplier<CredentialSource, ConfigXMLParseException> supplier, Supplier<Provider[]> providers) {
        this.name = checkNotNullParam("name", name);
        this.attributes = checkNotNullParam("attributes", attributes);
        this.type = type == null ? KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE : type;
        this.location = checkNotNullParam("location", location);
        this.credentialSource = supplier == null ? null : supplier;
        this.providerName = providerName;
        this.providers = providers;
    }

    /**
     * Create an instance of {@link CredentialStore} and initialize it.
     *
     * @return the new instance
     * @throws GeneralSecurityException if instantiation fails for some reason
     */
    @Override
    public CredentialStore get() throws ConfigXMLParseException {
        final CredentialStore credentialStore;
        try {
            if (providers != null) {
                credentialStore = providerName != null ? CredentialStore.getInstance(type, providerName, providers) : CredentialStore.getInstance(type, providers);
                credentialStore.initialize(attributes, credentialSource == null ? null : new CredentialStore.CredentialSourceProtectionParameter(credentialSource.get()), providers.get());
            } else {
                credentialStore = providerName != null ? CredentialStore.getInstance(type, providerName) : CredentialStore.getInstance(type);
                credentialStore.initialize(attributes, credentialSource == null ? null : new CredentialStore.CredentialSourceProtectionParameter(credentialSource.get()));
            }
        } catch (GeneralSecurityException e) {
            throw xmlLog.xmlFailedToCreateCredentialStore(location, e);
        }
        return credentialStore;
    }

    /**
     * Get name of {@link CredentialStore}
     * @return name
     */
    public String getName() {
        return name;
    }
}
