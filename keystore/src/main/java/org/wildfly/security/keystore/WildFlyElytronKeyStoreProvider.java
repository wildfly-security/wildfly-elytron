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

package org.wildfly.security.keystore;

import java.security.Provider;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.WildFlyElytronBaseProvider;

/**
 * Provider for {@code KeyStore} implementations.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronKeyStoreProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -2297626710941852090L;
    private static WildFlyElytronKeyStoreProvider INSTANCE = new WildFlyElytronKeyStoreProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronKeyStoreProvider() {
        super("WildFlyElytronKeyStoreProvider", "1.0", "WildFly Elytron KeyStore Provider");
        putService(new Service(this, "KeyStore", "PasswordFile", "org.wildfly.security.keystore.PasswordKeyStoreSpi", emptyList, emptyMap));
    }

    /**
     * Get the {@code KeyStore} implementations provider instance.
     *
     * @return the {@code KeyStore} implementations provider instance
     */
    public static WildFlyElytronKeyStoreProvider getInstance() {
        return INSTANCE;
    }

}
