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

import static org.wildfly.security._private.ElytronMessages.xmlLog;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Map;

import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.client.config.XMLLocation;
import org.wildfly.common.Assert;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;

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
    private final Provider provider;
    private final XMLLocation location;

    private CredentialStoreFactory(String name, String type, final Map<String, String> attributes, final Provider provider, String providerName, XMLLocation location) {
        Assert.checkNotNullParam("name", name);
        Assert.checkNotNullParam("attributes", attributes);
        this.name = name;
        this.type = type;
        this.attributes = attributes;
        if (provider != null) {
            this.provider = provider;
        } else {
            this.provider = Security.getProvider(providerName);
        }
        this.location = location;
    }

    /**
     * Creates a factory using parameters.
     *
     * @param name of the {@code CredentialStore}
     * @param type of the {@code CredentialStore}
     * @param attributes to initialize the {@code CredentialStore}
     * @param provider to load the instance from
     */
    CredentialStoreFactory(String name, String type, final Map<String, String> attributes, final Provider provider, XMLLocation location) {
        this(name, type, attributes, provider,  null, location);
    }

    /**
     * Creates a factory using parameters.
     *
     * @param name of the {@code CredentialStore}
     * @param type of the {@code CredentialStore}
     * @param attributes to initialize the {@code CredentialStore}
     * @param providerName to load the instance from
     */
    CredentialStoreFactory(String name, String type, Map<String, String> attributes, String providerName, XMLLocation location) {
        this(name, type, attributes, null, providerName, location);
    }

    /**
     * Creates a factory using parameters and default provider.
     *
     * @param name of the {@code CredentialStore}
     * @param type of the {@code CredentialStore}
     * @param attributes to initialize the {@code CredentialStore}
     */
    CredentialStoreFactory(String name, String type, Map<String, String> attributes, XMLLocation location) {
        this(name, type, attributes, null,  null, location);
    }

    /**
     * Create an instance of {@link CredentialStore} and initialize it.
     *
     * @return the new instance
     * @throws GeneralSecurityException if instantiation fails for some reason
     */
    @Override
    public CredentialStore get() throws ConfigXMLParseException {
        CredentialStore credentialStore;
        try {
            if (provider != null) {
                credentialStore = CredentialStore.getInstance(type, provider);
            } else {
                credentialStore = CredentialStore.getInstance(type);
            }
            credentialStore.initialize(attributes);
        } catch (GeneralSecurityException | CredentialStoreException e) {
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
