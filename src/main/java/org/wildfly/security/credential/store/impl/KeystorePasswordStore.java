/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.credential.store.impl;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * Keystore based {@link ClearPassword} password storage used in default Elytron Vault implementation.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class KeystorePasswordStore extends CredentialStoreSpi {

    /**
     * Type of {@link CredentialStoreSpi} implementation. Will be used as algorithm name when registering service in
     * {@link org.wildfly.security.WildFlyElytronProvider}.
     */
    public static final String KEY_STORE_PASSWORD_STORE = "KeyStorePasswordStore";

    /**
     * Versioned entry of {@link KeystorePasswordStore}.
     */
    public static class Entry implements Serializable {
        private static final int DEFAULT_VERSION = 1;
        private static final long serialVersionUID = -2347975176295725217L;
        private int version;
        private String className;
        private byte[] payload;

        /**
         * Constructor of {@code Entry} instance with default version of payload.
         * @param className class name of payload
         * @param payload data to construct entry when loading
         */
        public Entry(String className, byte[] payload) {
            this(DEFAULT_VERSION, className, payload);
        }

        /**
         * Constructor of {@code Entry} instance with specified version of payload.
         * @param version version of entry
         * @param className class name of payload
         * @param payload data to construct entry when loading
         */
        public Entry(int version, String className, byte[] payload) {
            this.version = version;
            this.className = className;
            this.payload = payload;
        }

        /**
         * Get entry version.
         * @return version
         */
        public int getVersion() {
            return version;
        }

        /**
         * Get name class name of the entry.
         * @return class name
         */
        public String getClassName() {
            return className;
        }

        /**
         * Get payload of the entry.
         * @return payload
         */
        public byte[] getPayload() {
            return payload;
        }

        /**
         * Creates {@code byte[]} of specified entry.
         * @param entry to serialize
         * @return {@code byte[]} serialized entry
         */
        public static byte[] serializeEntry(KeystorePasswordStore.Entry entry) {
            byte[] className = entry.getClassName().getBytes(StandardCharsets.UTF_8);
            ByteStringBuilder b = new ByteStringBuilder();
            b.appendBE(entry.getVersion());
            b.appendBE(className.length);
            b.append(className);
            b.append(entry.getPayload());
            return b.toArray();
        }

        /**
         * Creates new {@link Entry} from supplied data.
         * @param data to deserialize
         * @return new {@link Entry}
         */
        public static Entry deserializeEntry(byte[] data) {
            ByteIterator bi = ByteIterator.ofBytes(data);
            int version = bi.getBE32();
            int classNameLength = bi.getBE32();
            String className = bi.drainToUtf8(classNameLength);
            byte[] encrypted = bi.drain();
            return new Entry(version, className, encrypted);
        }

    }

    /**
     * Value of this attribute denotes name of the store.
     */
    public static final String NAME = "store.name";
    /**
     * Value of this attribute denotes file which is used as storage.
     */
    public static final String STORE_FILE = "store.file";
    /**
     * Value of this attribute is storage password.
     */
    public static final String STORE_PASSWORD = "store.password";
    /**
     * Value of this attribute denotes if this store can preform modification of its storage.
     */
    public static final String MODIFIABLE = "store.modifiable";
    /**
     * Value of this attribute denotes if base directory for STORE_FILE.
     */
    public static final String STORE_BASE = "store.base";

    /**
     * {@link KeystorePasswordStore} supported option
     */
    public static final String CREATE_STORAGE = "create.storage";
    /**
     * {@link KeystorePasswordStore} supported option
     */
    public static final String KEY_ALIAS = "key.alias";
    /**
     * {@link KeystorePasswordStore} supported option
     */
    public static final String KEY_PASSWORD = "key.password";
    /**
     * {@link KeystorePasswordStore} supported option
     */
    public static final String KEY_SIZE = "key.size";
    /**
     * {@link KeystorePasswordStore} supported option
     */
    public static final String CRYPTO_ALGORITHM = "crypto.algorithm";
    /**
     * {@link KeystorePasswordStore} supported option
     */
    public static final String RELOADABLE = "reloadable";
    /**
     * Default admin key alias for {@link KeystorePasswordStore}
     */
    public static final String DEFAULT_ADMIN_KEY_ALIAS = "ELY_ADMIN_KEY";

    private static final String KEYSTORE_TYPE = "JCEKS";
    private static final char[] EMPTY_PASSWORD = new char[0];
    private static final Set<String> supportedConfigurationAttributes;

    static {
        HashSet<String> ca = new HashSet<>();
        Collections.addAll(ca,
                NAME, STORE_FILE, STORE_PASSWORD, STORE_BASE,
                CREATE_STORAGE, KEY_ALIAS, KEY_PASSWORD,
                KEY_SIZE, CRYPTO_ALGORITHM, RELOADABLE);
        supportedConfigurationAttributes = Collections.unmodifiableSet(ca);
    }

    // used for reporting only / do not modify
    private String storeName;
    private boolean reloadable = false;
    private boolean modifiable = false;
    private File storeFile = null;
    private String storeBase = "";
    private char[] storagePassword = null;
    private String adminKeyAlias = null;
    private SecretKey adminKey = null;
    private int keySize = 128;
    private String cryptographicAlgorithm = "AES";
    private boolean createStorage = false;

    private KeyStore.ProtectionParameter adminKeyProtectionParam = null;

    private final ConcurrentHashMap<String, Entry> storage = new ConcurrentHashMap<>();

    /**
     * Construct a new instance.
     */
    public KeystorePasswordStore() {
    }

    @Override
    public void initialize(Map<String, String> attributes) throws CredentialStoreException {
        storeName = attributes.getOrDefault(NAME, "myStore");
        checkValidConfigurationAttributes(attributes.keySet());
        storeBase = attributes.get(STORE_BASE);
        storeFile = resolveFile(attributes.get(STORE_FILE), storeName);
        String pwdSpec = attributes.get(STORE_PASSWORD);
        if (pwdSpec != null) {
            storagePassword = convertPassword(loadPassword(pwdSpec, STORE_PASSWORD, attributes));
        }
        adminKeyAlias = (String) attributes.get(KEY_ALIAS);
        if (adminKeyAlias == null) {
            adminKeyAlias = DEFAULT_ADMIN_KEY_ALIAS;
        }

        if (attributes.get(KEY_SIZE) != null) {
            keySize = Integer.parseInt((String) attributes.get(KEY_SIZE));
        }

        if (attributes.get(CRYPTO_ALGORITHM) != null) {
            cryptographicAlgorithm = (String) attributes.get(CRYPTO_ALGORITHM);
        }

        if (attributes.get(MODIFIABLE) != null) {
            modifiable = Boolean.parseBoolean(attributes.get(MODIFIABLE));
        }

        if (attributes.get(CREATE_STORAGE) != null) {
            createStorage = Boolean.parseBoolean((String) attributes.get(CREATE_STORAGE));
        }

        pwdSpec = attributes.get(KEY_PASSWORD);
        if (pwdSpec != null) {
            char[] adminKeyPassword = convertPassword(loadPassword(pwdSpec, KEY_PASSWORD, attributes));
            adminKeyProtectionParam = new KeyStore.PasswordProtection(adminKeyPassword);
            destroyPassword(adminKeyPassword);
        }

        readKeyStore();
        initialized = true;
    }

    /**
     * Check if credential store service supports modification of its store
     *
     * @return {@code true} in case of modification of the store is supported, {@code false} otherwise
     */
    @Override
    public boolean isModifiable() {
        return modifiable;
    }

    @Override
    public <C extends Credential> boolean exists(String key, Class<C> credentialType)
            throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (credentialType.isAssignableFrom(PasswordCredential.class)) {
            return storage.get(key) != null;
        } else {
            throw new UnsupportedCredentialTypeException(resolveCredentialClassName(credentialType));
        }
    }

    @Override
    public <C extends Credential> void store(String credentialAlias, C credential)
            throws CredentialStoreException, UnsupportedCredentialTypeException {

        if (!isInitialized()) {
            log.credentialStoreNotInitialized(storeName);
        }
        if (!reloadable) {
            PasswordCredential passwordCredential;
            if (credential instanceof PasswordCredential) {
                passwordCredential = (PasswordCredential) credential;
            } else {
                throw new UnsupportedCredentialTypeException(resolveCredentialClassName(credential.getClass()));
            }
            try {
                storage.put(credentialAlias,
                        new Entry(resolveCredentialClassName(credential.getClass()),
                                encryptEntry(passwordCredential)));
            } catch (GeneralSecurityException e) {
                throw new CredentialStoreException(e);
            }
            storeToFile();
        } else {
            throw log.reloadablecredentialStoreIsReadOnly(storeName);
        }


    }

    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType)
            throws CredentialStoreException, UnsupportedCredentialTypeException {

        if (!credentialType.isAssignableFrom(PasswordCredential.class)) {
            throw new UnsupportedCredentialTypeException(resolveCredentialClassName(credentialType));
        }
        Entry entry = storage.get(credentialAlias);
        if (entry != null) {
            byte[] encryptedPasswordData = entry.getPayload();
            if (encryptedPasswordData != null) {
                try {
                    return credentialType.cast(decryptEntry(encryptedPasswordData));
                } catch (GeneralSecurityException e) {
                    throw new CredentialStoreException(e);
                }
            } else {
                throw log.credentialAliasNotFoundNotFound(credentialAlias, storeName);
            }
        } else {
            throw log.credentialAliasNotFoundNotFound(credentialAlias, storeName);
        }
    }

    @Override
    public <C extends Credential> void remove(String credentialAlias, Class<C> credentialType)
            throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (!credentialType.isAssignableFrom(PasswordCredential.class)) {
            throw new UnsupportedCredentialTypeException(resolveCredentialClassName(credentialType));
        }
        if (storage.get(credentialAlias) != null) {
            storage.remove(credentialAlias);
        }
    }

    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        return Collections.unmodifiableSet(storage.keySet());
    }

    private <C extends Credential> String resolveCredentialClassName(Class<C> credentialClass) throws UnsupportedCredentialTypeException {
        return credentialClass.getName();
    }

    private synchronized void storeToFile() throws CredentialStoreException, UnsupportedCredentialTypeException {

        if (createStorage && !storeFile.exists()) {
            try {
                storeFile.createNewFile();
            } catch (IOException e) {
                throw log.cannotWriteStorageFie(storeFile.getAbsolutePath(), storeName);
            }
        }

        try {
            KeyStore credentialStore = KeyStore.getInstance(KEYSTORE_TYPE);
            credentialStore.load(null, null);
            packToKeyStore(credentialStore);
            if (!storeFile.canWrite()) {
                throw log.cannotWriteStorageFie(storeFile.getAbsolutePath(), storeName);
            }
            credentialStore.store(new FileOutputStream(storeFile), storagePassword);
        } catch (GeneralSecurityException | IOException e) {
            throw new CredentialStoreException(e);
        }
    }

    private void packToKeyStore(KeyStore keyStore)
            throws KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedCredentialTypeException {
        // adminKey handling
        keyStore.setEntry(adminKeyAlias, new KeyStore.SecretKeyEntry(adminKey), adminKeyProtectionParam);
        // secret attributes
        for (String alias : storage.keySet()) {
            byte[] entryBytes = Entry.serializeEntry(storage.get(alias));
            keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(new SecretKeyWrap(entryBytes, ClearPassword.ALGORITHM_CLEAR)), adminKeyProtectionParam);
        }
    }

    private void checkValidConfigurationAttributes(Set<String> attributes) throws CredentialStoreException {
        StringBuilder wrongAttributes = new StringBuilder();
        attributes.stream()
                .filter(o -> !o.startsWith(STORE_PASSWORD + "."))   // namespace of STORE_PASSWORD
                .filter(o -> !o.startsWith(KEY_PASSWORD + "."))   // namespace of KEY_PASSWORD
                .filter(o -> !supportedConfigurationAttributes.contains(o)).forEach(o -> wrongAttributes.append(", ").append(o));
        if (wrongAttributes.length() > 0) {
            throw log.unsupportedPasswordStorageConfigurationAttributes(storeName, wrongAttributes.substring(2));
        }
    }

    private void readKeyStore() throws CredentialStoreException {

        if (createStorage && (!storeFile.exists() || !storeFile.canRead())) {
            // do not read key store, just generate adminKey
            try {
                adminKey = generateSecretKey();
            } catch (NoSuchAlgorithmException e) {
                log.info("Storage exception:", e);
                throw new CredentialStoreException(e);
            }
            return;
        }

        try {
            KeyStore vaultStorage = KeyStore.getInstance(KEYSTORE_TYPE);
            vaultStorage.load(new FileInputStream(storeFile), storagePassword);
            for (Enumeration<String> storedAliases = vaultStorage.aliases(); storedAliases.hasMoreElements();) {
                String alias = storedAliases.nextElement();
                if (!alias.equalsIgnoreCase(adminKeyAlias)) {
                    KeyStore.SecretKeyEntry secret = (KeyStore.SecretKeyEntry)vaultStorage.getEntry(alias, adminKeyProtectionParam);
                    if (secret.getSecretKey() != null) {
                        storage.put(alias, Entry.deserializeEntry(secret.getSecretKey().getEncoded()));
                    } else {
                        log.warn("Stored for alias='" + alias + "' is null.");
                    }
                }
            }

            adminKey = ((KeyStore.SecretKeyEntry) vaultStorage.getEntry(adminKeyAlias, adminKeyProtectionParam)).getSecretKey();
            if (adminKey == null) {
                throw log.storeAdminKeyNotPresent(storeName, adminKeyAlias);
            }

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException
                | UnrecoverableEntryException e) {
            throw log.cannotReadVaultStorage(storeFile.toString(), storeName, e);
        }

    }

    private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(cryptographicAlgorithm);
        generator.init(keySize);
        return generator.generateKey();
    }

    /**
     * Encrypt {@code entry} by encoding it using UTF-8 to {@code byte[]}
     * {@code char[]} is first encoded to {@code byte[]} using {@link java.nio.charset.StandardCharsets}.UTF_8 character set.
     *
     * @param passwordCredential {@link PasswordCredential} to encrypt
     * @return encrypted value
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    private byte[] encryptEntry(PasswordCredential passwordCredential) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Assert.assertNotNull(passwordCredential);
        Cipher c = getCipher(Cipher.ENCRYPT_MODE);
        if (ClearPassword.ALGORITHM_CLEAR.equals(passwordCredential.getAlgorithm())) {
            Password p = passwordCredential.getPassword();
            return c.doFinal(charArrayEncode(((ClearPassword) p).getPassword()));
        } else {
            throw new NoSuchAlgorithmException(passwordCredential.getAlgorithm());
        }
    }

    /**
     * Decrypting secret entry directly to {@code ClearPassword}.
     * {@code byte[]} is encoded to {@code char[]} using {@link java.nio.charset.StandardCharsets}.UTF_8 character set.
     *
     * @param entry to decrypt
     * @return decrypted {@link ClearPassword} instance
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private PasswordCredential decryptEntry(byte[] entry) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        Assert.assertNotNull(entry);
        Cipher c = getCipher(Cipher.DECRYPT_MODE);

        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(byteArrayDecode(c.doFinal(entry)))));
    }

    static char[] byteArrayDecode(byte[] buffer) {
        return new String(buffer, StandardCharsets.UTF_8).toCharArray();
    }

    static byte[] charArrayEncode(char[] buffer) {
        return Normalizer.normalize(new String(buffer), Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
    }

    private Cipher getCipher(int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec adminKeySpec = new SecretKeySpec(adminKey.getEncoded(), cryptographicAlgorithm);
        Cipher c = Cipher.getInstance(cryptographicAlgorithm);
        c.init(mode, adminKeySpec);
        return c;
    }

    private void destroyPassword(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\u0000');
        }
    }

    private Credential loadPassword(final String credentialSpec, final String nameSpace, final Map<String, String> options) throws CredentialStoreException {
        Map<String, String> nameSpaceOnlyOptions;
        nameSpaceOnlyOptions = options.entrySet().stream()
                .filter(p -> !p.getKey().equals(nameSpace) && p.getKey().startsWith(nameSpace))
                .collect(Collectors.toMap(p -> p.getKey().substring(nameSpace.length()+1), Map.Entry::getValue));
        return resolveMasterCredential(credentialSpec, PasswordCredential.class, nameSpaceOnlyOptions);
    }

    private char[] convertPassword(Object password) {
        if (password != null) {
            if (password instanceof String) {
                return ((String) password).toCharArray();
            } else if (password instanceof ClearPassword) {
                return ((ClearPassword) password).getPassword();
            } else if (password instanceof PasswordCredential) {
                Password p = ((PasswordCredential)password).getPassword();
                if (p instanceof ClearPassword) {
                    return ((ClearPassword) p).getPassword();
                } else {
                    return EMPTY_PASSWORD;
                }
            } else {
                return Arrays.copyOf((char[]) password, ((char[]) password).length);
            }
        } else {
            return EMPTY_PASSWORD;
        }
    }

    private File resolveFile(String fileName, String defaultFileName) {
        String storage = (storeBase != null && !storeBase.isEmpty() ? storeBase + "/" : "") + (fileName != null ? fileName : defaultFileName);
        return new File(storage);
    }
}
