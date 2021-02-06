/*
 * Copyright 2021 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.credential.store.impl;

import static org.wildfly.security.credential.store._private.ElytronMessages.log;
import static org.wildfly.security.encryption.SecretKeyUtil.exportSecretKey;
import static org.wildfly.security.encryption.SecretKeyUtil.importSecretKey;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.SecretKey;

import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStore.ProtectionParameter;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;

/**
 * A {@link CredentialStore} implementation backed by a properties file.
 *
 * This is a simple implementation which only supports the storage of {@code SecretKey} credentials, additionally
 * password protection of the store is not supported.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PropertiesCredentialStore extends CredentialStoreSpi {

    private final String HEADER = "# Properties Credential Store (Do Not Modify)";
    private static final char COMMENT = '#';
    private static final char DELIMITER = '=';

    private static final String CREATE = "create";
    private static final String LOCATION = "location";

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final AtomicReference<Map<String, SecretKey>> entries = new AtomicReference<>();
    private volatile File credentialStoreLocation;

    @Override
    public void initialize(Map<String, String> attributes, ProtectionParameter protectionParameter, Provider[] providers) throws CredentialStoreException {
        try (Lock lock = lockForWrite()) {
            String location = attributes.get(LOCATION);
            if (location == null) {
                throw log.missingInitialisationAttribute(LOCATION);
            }
            boolean create = Boolean.parseBoolean(attributes.getOrDefault(CREATE, Boolean.FALSE.toString()));
            File credentialStoreLocation = new File(location);
            boolean exists = credentialStoreLocation.exists();
            if (!create && !exists) {
                throw log.automaticStorageCreationDisabled(location);
            }
            this.credentialStoreLocation = credentialStoreLocation;

            if (exists) {
                entries.set(load());
            } else {
                entries.set(new LinkedHashMap<>());
                save();
            }

            initialized = true;
        } catch (IOException e) {
            throw log.cannotInitializeCredentialStore(e);
        }
    }

    @Override
    public boolean isModifiable() {
        return true;
    }

    @Override
    public void store(String credentialAlias, Credential credential, ProtectionParameter protectionParameter)
            throws CredentialStoreException, UnsupportedCredentialTypeException {
        final Class<? extends Credential> credentialClass = credential.getClass();
        if (credentialClass == SecretKeyCredential.class) {
            try (Lock lock = lockForWrite()) {
                assertInitialised();
                entries.get().put(credentialAlias, ((SecretKeyCredential) credential).getSecretKey());
            }
        } else {
            throw log.unsupportedCredentialType(credentialClass);
        }
    }

    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType, String credentialAlgorithm,
            AlgorithmParameterSpec parameterSpec, ProtectionParameter protectionParameter) throws CredentialStoreException {
        if (credentialType.isAssignableFrom(SecretKeyCredential.class)) {
            try (Lock lock = lockForRead()) {
                assertInitialised();
                SecretKey secretKey = entries.get().get(credentialAlias);
                if (secretKey != null) {
                    SecretKeyCredential credential = new SecretKeyCredential(secretKey);

                    return credentialType.cast(credential);
                }
            }
        } else {
            throw log.unsupportedCredentialType(credentialType);
        }

        return null;
    }

    @Override
    public void remove(String credentialAlias, Class<? extends Credential> credentialType, String credentialAlgorithm,
            AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {

        if (credentialType.isAssignableFrom(SecretKeyCredential.class)) {
            try (Lock lock = lockForWrite()) {
                assertInitialised();
                entries.get().remove(credentialAlias);
            }
        } else {
            throw log.unsupportedCredentialType(credentialType);
        }
    }


    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        try (Lock lock = lockForRead()) {
            assertInitialised();

            return new HashSet<String>(entries.get().keySet());
        }
    }

    @Override
    public void flush() throws CredentialStoreException {
        try (Lock lock = lockForWrite()) {
            assertInitialised();
            save();
        } catch (IOException e) {
            throw log.cannotFlushCredentialStore(e);
        }
    }

    private void save() throws IOException {
        try (PrintWriter pw = new PrintWriter(credentialStoreLocation)) {
            pw.println(HEADER);
            for (Entry<String, SecretKey> entry : entries.get().entrySet() ) {
                pw.print(entry.getKey());
                pw.print(DELIMITER);
                pw.println(exportSecretKey(entry.getValue()));
            }
        }
    }

    private Map<String, SecretKey> load() throws CredentialStoreException, IOException {
        Map<String, SecretKey> entries = new LinkedHashMap<>();
        try (FileReader fr = new FileReader(credentialStoreLocation); BufferedReader bis = new BufferedReader(fr)) {
            String line;
            skip:
            while ((line = bis.readLine()) != null) {
                char[] currentLine = line.toCharArray();
                int start = -1;
                int delimiter = -1;
                int end = -1;

                // From beginning search for start of line and delimiter.
                for (int i = 0; (i < currentLine.length && delimiter < 0); i++) {
                    if (start < 0) {
                        if (currentLine[i] == COMMENT) {
                            continue skip;
                        } else if (!Character.isWhitespace(currentLine[i])) {
                            start = i;
                        }
                    }
                    if (currentLine[i]==DELIMITER) {
                        delimiter = i;
                    }
                }

                // From end search for non-whitespace.
                if (delimiter > 0) {
                    for (int i = currentLine.length - 1; (i > delimiter && end < 0); i--) {
                        if (!Character.isWhitespace(currentLine[i])) {
                            end = i;
                        }
                    }
                }

                if (start > -1 && delimiter > -1 && end > -1) {
                    String alias = new String(currentLine, start, delimiter - start);
                    SecretKey secretKey = importSecretKey(currentLine, delimiter, end - delimiter);
                    entries.put(alias, secretKey);
                } else {
                    throw log.invalidCredentialStoreProperty(line);
                }
            }
        }
        return entries;
    }

    private void assertInitialised() throws CredentialStoreException {
        if (initialized == false) {
            throw log.storeNotInitialised();
        }
    }

    interface Lock extends AutoCloseable { void close(); }

    private Lock lockForRead() {
        readWriteLock.readLock().lock();
        return () -> readWriteLock.readLock().unlock();
    }

    private Lock lockForWrite() {
        readWriteLock.writeLock().lock();
        return () -> readWriteLock.writeLock().unlock();
    }

}
