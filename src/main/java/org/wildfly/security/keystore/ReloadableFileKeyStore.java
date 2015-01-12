/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

/**
 * A file base {@link KeyStore} that supports dynamic reloading when changes to the underlying store are detected.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ReloadableFileKeyStore extends KeyStore implements Closeable {

    private final ReloadableKeyStoreSpiImpl keyStoreSpi;

    private ReloadableFileKeyStore(ReloadableKeyStoreSpiImpl keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);
        this.keyStoreSpi = keyStoreSpi;
    }

    public static ReloadableFileKeyStore getInstance(String type, Provider provider, File storeLocation, char[] storePassword)
            throws KeyStoreException {
        ReloadableKeyStoreSpiImpl spi = new ReloadableKeyStoreSpiImpl(type, provider, storeLocation, storePassword);

        return new ReloadableFileKeyStore(spi, provider, type);
    }

    public static ReloadableFileKeyStore getInstance(String type, File storeLocation, char[] storePassword)
            throws KeyStoreException {
        return getInstance(type, null, storeLocation, storePassword);
    }

    public void close() throws IOException {
        keyStoreSpi.close();
    }

}
