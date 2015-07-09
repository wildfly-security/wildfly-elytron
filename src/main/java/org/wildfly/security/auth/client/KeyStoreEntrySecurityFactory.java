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

package org.wildfly.security.auth.client;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import org.wildfly.security.FixedSecurityFactory;
import org.wildfly.security.SecurityFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class KeyStoreEntrySecurityFactory implements SecurityFactory<KeyStore.Entry> {

    private final SecurityFactory<KeyStore> keyStore;
    private final String alias;
    private final SecurityFactory<KeyStore.ProtectionParameter> protectionParameter;

    KeyStoreEntrySecurityFactory(final KeyStore keyStore, final String alias, final KeyStore.ProtectionParameter protectionParameter) {
        this(new FixedSecurityFactory<KeyStore>(keyStore), alias, new FixedSecurityFactory<KeyStore.ProtectionParameter>(protectionParameter));
    }

    KeyStoreEntrySecurityFactory(final SecurityFactory<KeyStore> keyStore, final String alias, final SecurityFactory<KeyStore.ProtectionParameter> protectionParameter) {
        this.keyStore = keyStore;
        this.alias = alias;
        this.protectionParameter = protectionParameter;
    }

    public KeyStore.Entry create() throws GeneralSecurityException {
        return keyStore.create().getEntry(alias, protectionParameter == null ? null : protectionParameter.create());
    }
}
