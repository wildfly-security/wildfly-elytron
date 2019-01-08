/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security;

import java.security.Provider;

import org.kohsuke.MetaInfServices;

/**
 * Provider for credential store implementations.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronCredentialStoreProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -3770297685039711294L;
    private static WildFlyElytronCredentialStoreProvider INSTANCE = new WildFlyElytronCredentialStoreProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronCredentialStoreProvider() {
        super("WildFlyElytronCredentialStoreProvider", "1.0", "WildFly Elytron CredentialStore Provider");
        putService(new Service(this, "CredentialStore", "KeyStoreCredentialStore", "org.wildfly.security.credential.store.impl.KeyStoreCredentialStore", emptyList, emptyMap));
        putService(new Service(this, "CredentialStore", "VaultCredentialStore", "org.wildfly.security.credential.store.impl.VaultCredentialStore", emptyList, emptyMap));
        putService(new Service(this, "CredentialStore", "MapCredentialStore", "org.wildfly.security.credential.store.impl.MapCredentialStore", emptyList, emptyMap));

        putService(new Service(this, "KeyStore", "PasswordFile", "org.wildfly.security.keystore.PasswordKeyStoreSpi", emptyList, emptyMap));
        putAlgorithmParametersImplementations();
        putPasswordImplementations();
    }

    /**
     * Get the credential store implementations provider instance.
     *
     * @return the credential store implementations provider instance
     */
    public static WildFlyElytronCredentialStoreProvider getInstance() {
        return INSTANCE;
    }

}
