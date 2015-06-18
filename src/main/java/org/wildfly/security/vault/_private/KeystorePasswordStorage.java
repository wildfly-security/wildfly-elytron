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
package org.wildfly.security.vault._private;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.storage.PasswordStorageSpi;
import org.wildfly.security.storage.StorageException;
import org.wildfly.security.storage.UnsupportedPasswordClassException;
import org.wildfly.security.vault.PasswordClass;
import org.wildfly.security.vault.VaultCallbackHandler;
import org.wildfly.security.vault.VaultException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * Keystore based {@link ClearPassword} password storage used in default Elytron Vault implementation.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class KeystorePasswordStorage extends PasswordStorageSpi {
    /**
     * Value of this option denotes file which is used as vault storage.
     */
    public static final String NAME = "name";
    /**
     * Value of this option denotes file which is used as vault storage.
     */
    public static final String STORAGE_FILE = "storage.file";
    /**
     * Value of this option is storage password. Could be omitted but {@code CALLBACK} has to specified.
     */
    public static final String STORAGE_PASSWORD = "storage.password";
    /**
     *  Format of this option is either {@code [class]} or {@code [class]@[module]}
     *  Default callback handler if {@link VaultCallbackHandler}.
     */
    public static final String CALLBACK_HANDLER = "handler";
    /**
     *  Format of this option is either {@code [class]} or {@code [class]@[module]}
     */
    public static final String CALLBACK = "callback";
    /**
     *  Password class specification. This class has to implement {@link PasswordClass} interface.
     *  Format of this option is either {@code [class]} or {@code [class]@[module]}
     */
    public static final String CALLBACK_PASSWORD_CLASS = CALLBACK + ".passwordClass";
    /**
     * Masked password option name.
     */
    public static final String CALLBACK_MASKED = CALLBACK + ".maskedPassword";
    /**
     * Salt option name.
     */
    public static final String CALLBACK_SALT = CALLBACK + ".salt";
    /**
     * Iteration count option name.
     */
    public static final String CALLBACK_ITERATION = CALLBACK + ".iteration";
    /**
     * PBE algorithm option name.
     */
    public static final String CALLBACK_PBE_ALGORITHM = CALLBACK + ".algorithm";
    /**
     * PBE initial key material option name.
     */
    public static final String CALLBACK_PBE_INITIAL_KEY = CALLBACK + ".initialKey";

    /**
     * Algorithm/type of this {@link PasswordStorageSpi} implementation.
     */
    public static final String KEY_STORE_PASSWORD_STORAGE = "KeyStorePasswordStorage";

    // ElytronVault options
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String CREATE_STORAGE = "create.storage";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_ALIAS = "key.alias";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD = "key.password";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD_CALLBACK = KEY_PASSWORD + ".callback";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD_CALLBACK_HANDLER = KEY_PASSWORD_CALLBACK + ".handler";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD_CALLBACK_PASSWORD_CLASS = KEY_PASSWORD_CALLBACK + ".passwordClass";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD_MASKED = KEY_PASSWORD + ".maskedPassword";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD_SALT = KEY_PASSWORD + ".salt";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD_ITERATION = KEY_PASSWORD + ".iteration";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD_PBE_ALGORITHM = KEY_PASSWORD + ".algorithm";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_PASSWORD_PBE_INITIAL_KEY = KEY_PASSWORD +".initialKey";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String KEY_SIZE = "key.size";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String CRYPTO_ALGORITHM = "crypto.algorithm";
    /**
     * {@link KeystorePasswordStorage} supported option
     */
    public static final String RELOADABLE = "reloadable";
    /**
     * Default admin key alias for {@link KeystorePasswordStorage}
     */
    public static final String DEFAULT_ADMIN_KEY_ALIAS = "ELY_ADMIN_KEY";

    private static final String KEYSTORE_TYPE = "JCEKS";
    private static final char[] CHARS = new char[0];
    private static HashSet<String> supportedConfigurationAttributes = new HashSet<>();

    static {
        Collections.addAll(supportedConfigurationAttributes,
                // KeystorePasswordStorage options
                NAME, STORAGE_FILE, STORAGE_PASSWORD,
                CREATE_STORAGE, KEY_ALIAS, KEY_PASSWORD, KEY_PASSWORD_CALLBACK, KEY_PASSWORD_CALLBACK_HANDLER, KEY_PASSWORD_CALLBACK_PASSWORD_CLASS,
                KEY_PASSWORD_MASKED, KEY_PASSWORD_SALT, KEY_PASSWORD_ITERATION, KEY_PASSWORD_PBE_ALGORITHM, KEY_PASSWORD_PBE_INITIAL_KEY,
                KEY_SIZE, CRYPTO_ALGORITHM, RELOADABLE);
    }

    // used for reporting only / do not modify
    private String vaultName;
    private boolean reloadable = false;
    private File storageFile = null;
    private char[] storagePassword = null;
    private String adminKeyAlias = null;
    private SecretKey adminKey = null;
    private int keySize = 128;
    private String cryptographicAlgorithm = "AES";
    private boolean createStorage = false;

    private KeyStore.ProtectionParameter adminKeyProtectionParam = null;

    private final ConcurrentHashMap<String, byte[]> storage = new ConcurrentHashMap<>();

    /**
     * Construct a new instance.
     */
    public KeystorePasswordStorage() {
    }

    @Override
    public void initialize(Map<String, String> attributes) throws StorageException {
        checkValidConfigurationAttributes(attributes.keySet());

        vaultName = attributes.getOrDefault(NAME, "defaultStorageName");
        storageFile = new File((String) attributes.get(STORAGE_FILE));
        storagePassword = convertPassword(attributes.get(STORAGE_PASSWORD));
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

        if (attributes.get(CREATE_STORAGE) != null) {
            createStorage = Boolean.parseBoolean((String) attributes.get(CREATE_STORAGE));
        }

        char[] adminKeyPassword = loadKeyPassword(attributes);
        if (adminKeyPassword != null) {
            adminKeyProtectionParam = new KeyStore.PasswordProtection(adminKeyPassword);
            destroyPassword(adminKeyPassword);
        }

        readKeyStore();

        initialized = true;
    }

    @Override
    public <T extends Password> boolean exists(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException {
        if (passwordClass.isAssignableFrom(ClearPassword.class)) {
            return storage.get(key) != null;
        } else {
            throw new UnsupportedPasswordClassException(resolvePasswordClassName(passwordClass));
        }
    }

    @Override
    public <T extends Password> void store(String key, Class<T> passwordClass, T password) throws StorageException, UnsupportedPasswordClassException {

        if (!isInitialized()) {
            log.vaultIsNotInitialized(vaultName);
        }
        if (!reloadable) {
            if (! passwordClass.isAssignableFrom(ClearPassword.class)) {
                throw new UnsupportedPasswordClassException(resolvePasswordClassName(passwordClass));
            }
            ClearPassword clearPassword;
            if (password instanceof ClearPassword) {
                clearPassword = (ClearPassword)password;
            } else {
                throw new UnsupportedPasswordClassException(resolvePasswordClassName(passwordClass));
            }
            try {
                storage.put(key, encryptEntry(clearPassword, null));
            } catch (GeneralSecurityException e) {
                throw new StorageException(e);
            }
            storeToFile();
        } else {
            throw log.reloadableVaultIsReadOnly(vaultName);
        }


    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends Password> T retrieve(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException {
        if (!passwordClass.isAssignableFrom(ClearPassword.class)) {
            throw new UnsupportedPasswordClassException(resolvePasswordClassName(passwordClass));
        }
        byte[] encryptedPasswordData = storage.get(key);
        if (encryptedPasswordData != null) {
            try {
                return (T) decryptEntry(encryptedPasswordData, null);
            } catch (GeneralSecurityException e) {
                throw new StorageException(e);
            }
        } else {
            throw log.securedAttributeNotFound(key, vaultName);
        }
    }

    @Override
    public <T extends Password> void remove(String key, Class<T> passwordClass) throws StorageException, UnsupportedPasswordClassException {
        if (!passwordClass.isAssignableFrom(ClearPassword.class)) {
            throw new UnsupportedPasswordClassException(resolvePasswordClassName(passwordClass));
        }
        if (storage.get(key) != null) {
            storage.remove(key);
        }
    }

    private <T extends Password> String resolvePasswordClassName(Class<T> passwordClass) throws UnsupportedPasswordClassException {
        if (passwordClass.isInterface()) {

        }
        return passwordClass.getName();
    }

    private synchronized void storeToFile() throws StorageException {

        if (createStorage && !storageFile.exists()) {
            try {
                storageFile.createNewFile();
            } catch (IOException e) {
                throw log.cannotWriteVaultStorage(vaultName, storageFile.getAbsolutePath());
            }
        }

        try {
            KeyStore vaultStorage = KeyStore.getInstance(KEYSTORE_TYPE);
            vaultStorage.load(null, null);
            packToKeyStore(vaultStorage);
            if (!storageFile.canWrite()) {
                throw log.cannotWriteVaultStorage(vaultName, storageFile.getAbsolutePath());
            }
            vaultStorage.store(new FileOutputStream(storageFile), storagePassword);
        } catch (GeneralSecurityException | IOException e) {
            throw new StorageException(e);
        }
    }

    private void packToKeyStore(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedPasswordClassException {
        // adminKey handling
        keyStore.setEntry(adminKeyAlias, new KeyStore.SecretKeyEntry(adminKey), adminKeyProtectionParam);
        // secret attributes
        final PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Set<String> vaultKeys = storage.keySet();
        for (String key : vaultKeys) {
            ClearPassword password = (ClearPassword)passwordFactory.generatePassword(new ClearPasswordSpec(byteArrayDecode(storage.get(key))));
            keyStore.setEntry(key, new KeyStore.SecretKeyEntry(wrapPassword(password)), adminKeyProtectionParam);
        }
    }

    private void checkValidConfigurationAttributes(Set<String> attributes) throws StorageException {
        StringBuilder wrongAttributes = new StringBuilder();
        for (String o : attributes) {
            if (!o.startsWith(KEY_PASSWORD_CALLBACK) && !supportedConfigurationAttributes.contains(o)) {
                wrongAttributes.append(", ").append(o);
            }
        }
        if (wrongAttributes.length() > 0) {
            throw log.unsupportedPasswordStorageConfigurationAttributes(vaultName, wrongAttributes.substring(2));
        }
    }

    private void readKeyStore() throws StorageException {

        if (createStorage && (!storageFile.exists() || !storageFile.canRead())) {
            // do not read key store, just generate adminKey
            try {
                adminKey = generateSecretKey();
            } catch (NoSuchAlgorithmException e) {
                log.info("Storage exception:", e);
                throw new StorageException(e);
            }
            return;
        }

        try {
            KeyStore vaultStorage = KeyStore.getInstance(KEYSTORE_TYPE);
            vaultStorage.load(new FileInputStream(storageFile), storagePassword);
            for (Enumeration<String> storedAliases = vaultStorage.aliases(); storedAliases.hasMoreElements();) {
                String alias = storedAliases.nextElement();
                if (!alias.equalsIgnoreCase(adminKeyAlias)) {
                    KeyStore.SecretKeyEntry secret = (KeyStore.SecretKeyEntry)vaultStorage.getEntry(alias, adminKeyProtectionParam);
                    storage.put(alias, secret.getSecretKey().getEncoded());
                }
            }

            adminKey = ((KeyStore.SecretKeyEntry) vaultStorage.getEntry(adminKeyAlias, adminKeyProtectionParam)).getSecretKey();
            if (adminKey == null) {
                throw log.vaultAdminKeyNotPresent(vaultName, adminKeyAlias);
            }

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException
                | UnrecoverableEntryException e) {
            throw log.cannotReadVaultStorage(vaultName, storageFile.toString(), e);
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
     * @param clearPassword {@link ClearPassword} to encrypt
     * @param cipher {@link Cipher} to encrypt the entry
     * @return encrypted value
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    private byte[] encryptEntry(ClearPassword clearPassword, Cipher cipher) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = (cipher != null ? cipher : getCipher(Cipher.ENCRYPT_MODE));
        return c.doFinal(charArrayEncode(clearPassword.getPassword()));
    }

    /**
     * Decrypting secret entry directly to {@code ClearPassword}.
     * {@code byte[]} is encoded to {@code char[]} using {@link java.nio.charset.StandardCharsets}.UTF_8 character set.
     *
     * @param entry to decrypt
     * @param cipher {@link Cipher} to decrypt the entry
     * @return decrypted {@link ClearPassword} instance
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private ClearPassword decryptEntry(byte[] entry, Cipher cipher) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        Cipher c = (cipher != null ? cipher : getCipher(Cipher.DECRYPT_MODE));
        ClearPassword clearPassword = (ClearPassword) PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR)
                .generatePassword(new ClearPasswordSpec(byteArrayDecode(c.doFinal(entry))));
        return clearPassword;
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

    private char[] convertPassword(Object password) {
        if (password != null) {
            if (password instanceof String) {
                return ((String) password).toCharArray();
            } else if (password instanceof ClearPassword) {
                return ((ClearPassword) password).getPassword();
            } else {
                return Arrays.copyOf((char[]) password, ((char[]) password).length);
            }
        } else {
            return CHARS;
        }
    }

    private SecretKey wrapPassword(final ClearPassword password) {
        return new SecretKeyWrap(password);
    }

    private char[] loadKeyPassword(final Map<String, String> options) throws StorageException {
        ExternalPasswordLoader passwordLoader = new ExternalPasswordLoader(
                KEY_PASSWORD_CALLBACK,
                KEY_PASSWORD_CALLBACK_HANDLER,
                KEY_PASSWORD_CALLBACK_PASSWORD_CLASS,
                KEY_PASSWORD,
                KEY_PASSWORD_MASKED, KEY_PASSWORD_SALT, KEY_PASSWORD_ITERATION, KEY_PASSWORD_PBE_ALGORITHM, KEY_PASSWORD_PBE_INITIAL_KEY);
        try {
            return passwordLoader.loadPassword(options);
        } catch (VaultException | IllegalAccessException | InstantiationException | IOException | UnsupportedCallbackException | NoSuchMethodException e) {
            throw new StorageException(e);
        }
    }

}
