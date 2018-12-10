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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.util.AtomicFileOutputStream;

/**
 * Credential store implementation which uses the legacy "vault" format.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class VaultCredentialStore extends CredentialStoreSpi {
    public static final String VAULT_CREDENTIAL_STORE = "VaultCredentialStore";

    private static final String LOCATION = "location";
    private static final List<String> validAttribtues = Arrays.asList(LOCATION);

    // synchronize all accesses, particularly during load/store
    private final Map<String, byte[]> data = new HashMap<>();

    private SecretKey adminKey;
    private File location;
    private volatile boolean modifiable;

    /**
     * Construct a new instance.
     */
    public VaultCredentialStore() {
    }

    public void initialize(final Map<String, String> attributes, final CredentialStore.ProtectionParameter protectionParameter, Provider[] providers) throws CredentialStoreException {
        if (! (protectionParameter instanceof CredentialStore.CredentialSourceProtectionParameter)) {
            throw log.invalidProtectionParameter(protectionParameter);
        }
        final CredentialSource credentialSource = ((CredentialStore.CredentialSourceProtectionParameter) protectionParameter).getCredentialSource();
        final SecretKey secretKey;
        try {
            secretKey = credentialSource.applyToCredential(SecretKeyCredential.class, "AES", SecretKeyCredential::getSecretKey);
        } catch (IOException e) {
            throw log.cannotAcquireCredentialFromStore(e);
        }
        if (secretKey == null) {
            throw log.cannotAcquireCredentialFromStore(null);
        }
        validateAttribute(attributes, validAttribtues);
        final String location = attributes.get(LOCATION);
        if (location != null) {
            final File locationFile = new File(location, "VAULT.dat");
            if (locationFile.exists()) {
                // try and load it
                SecurityVaultData data;
                try (final FileInputStream is = new FileInputStream(locationFile)) {
                    try (final VaultObjectInputStream ois = new VaultObjectInputStream(is)) {
                        data = (SecurityVaultData) ois.readObject();
                    }
                } catch (ClassNotFoundException | IOException e) {
                    throw log.cannotAcquireCredentialFromStore(e);
                }
                if (data != null) {
                    synchronized (this.data) {
                        this.data.clear();
                        this.data.putAll(data.getVaultData());
                    }
                }
                this.location = locationFile;
                this.modifiable = locationFile.canWrite();
            }
        }
        this.adminKey = secretKey;
    }

    public boolean isModifiable() {
        return modifiable;
    }

    public void store(final String credentialAlias, final Credential credential, final CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (! modifiable) {
            throw log.nonModifiableCredentialStore("store");
        }
        if (protectionParameter != null) {
            throw log.invalidProtectionParameter(protectionParameter);
        }
        // Vault can only store clear passwords; let's check out the type first.
        final char[] chars = credential.castAndApply(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        if (chars == null) {
            throw log.unsupportedCredentialType(credential.getClass());
        }
        byte[] encoded;
        try {
            final Cipher cipher = Cipher.getInstance(adminKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, adminKey);
            encoded = cipher.doFinal(CodePointIterator.ofChars(chars).asUtf8().drain());
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException e) {
            throw log.cannotWriteCredentialToStore(e);
        }
        synchronized (data) {
            data.put(credentialAlias, encoded);
        }
    }

    public <C extends Credential> C retrieve(final String credentialAlias, final Class<C> credentialType, final String credentialAlgorithm, final AlgorithmParameterSpec parameterSpec, final CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        if (protectionParameter != null) {
            throw log.invalidProtectionParameter(protectionParameter);
        }
        if (! credentialType.isAssignableFrom(PasswordCredential.class)) {
            return null;
        }
        if (credentialAlgorithm != null && ! credentialAlgorithm.equals(ClearPassword.ALGORITHM_CLEAR)) {
            return null;
        }
        if (parameterSpec != null) {
            return null;
        }
        final byte[] bytes;
        synchronized (data) {
            bytes = data.get(credentialAlias);
        }
        // decode
        final byte[] decoded;
        try {
            final Cipher cipher = Cipher.getInstance(adminKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, adminKey);
            decoded = cipher.doFinal(bytes);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException e) {
            throw log.cannotAcquireCredentialFromStore(e);
        }
        return credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, new String(decoded, StandardCharsets.UTF_8).toCharArray())));
    }

    public void remove(final String credentialAlias, final Class<? extends Credential> credentialType, final String credentialAlgorithm, final AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        if (! credentialType.isAssignableFrom(PasswordCredential.class)) {
            return;
        }
        if (credentialAlgorithm != null && ! credentialAlgorithm.equals(ClearPassword.ALGORITHM_CLEAR)) {
            return;
        }
        if (parameterSpec != null) {
            return;
        }
        synchronized (data) {
            data.remove(credentialAlias);
        }
    }

    public void flush() throws CredentialStoreException {
        synchronized (data) {
            final File location = this.location;
            if (location != null) {
                try (final AtomicFileOutputStream os = new AtomicFileOutputStream(location)) {
                    try (final VaultObjectOutputStream oos = new VaultObjectOutputStream(os)) {
                        oos.writeObject(new SecurityVaultData(data));
                    } catch (Throwable t) {
                        os.cancel();
                        throw t;
                    }
                } catch (IOException e) {
                    throw log.cannotWriteCredentialToStore(e);
                }
            }
        }
    }

    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        synchronized (data) {
            return data.keySet();
        }
    }

}
