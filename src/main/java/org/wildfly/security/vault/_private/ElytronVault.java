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

import org.kohsuke.MetaInfServices;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.vault.VaultException;
import org.wildfly.security.vault.VaultSpi;

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
 * Implementation of {@link VaultSpi} interface.
 *
 * This class is default {@code Elytron} implementation of VaultSpi. It is using JCEKS type {@link KeyStore} to store secret attributes.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
@MetaInfServices(value = VaultSpi.class)
public class ElytronVault implements VaultSpi {

    // ElytronVault options
    /**
     * {@link ElytronVault} supported option
     */
    public static final String CREATE_STORAGE = "create.storage";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_ALIAS = "key.alias";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD = "key.password";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD_CALLBACK = KEY_PASSWORD + ".callback";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD_CALLBACK_HANDLER = KEY_PASSWORD_CALLBACK + ".handler";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD_CALLBACK_PASSWORD_CLASS = KEY_PASSWORD_CALLBACK + ".passwordClass";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD_MASKED = KEY_PASSWORD + ".maskedPassword";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD_SALT = KEY_PASSWORD + ".salt";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD_ITERATION = KEY_PASSWORD + ".iteration";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD_PBE_ALGORITHM = KEY_PASSWORD + ".algorithm";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_PASSWORD_PBE_INITIAL_KEY = KEY_PASSWORD +".initialKey";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String KEY_SIZE = "key.size";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String CRYPTO_ALGORITHM = "crypto.algorithm";
    /**
     * {@link ElytronVault} supported option
     */
    public static final String RELOADABLE = "reloadable";
    /**
     * Default admin key alias for {@link ElytronVault}
     */
    public static final String DEFAULT_ADMIN_KEY_ALIAS = "ELY_ADMIN_KEY";

    private static final String KEYSTORE_TYPE = "JCEKS";
    private static final char[] CHARS = new char[0];
    private static HashSet<String> supportedOptions = new HashSet<>();

    static {
        Collections.addAll(supportedOptions,
                // general VaultSpi options
                NAME, STORAGE_FILE, STORAGE_PASSWORD,
                // ElytronVault options
                CREATE_STORAGE, KEY_ALIAS, KEY_PASSWORD, KEY_PASSWORD_CALLBACK, KEY_PASSWORD_CALLBACK_HANDLER, KEY_PASSWORD_CALLBACK_PASSWORD_CLASS,
                KEY_PASSWORD_MASKED, KEY_PASSWORD_SALT, KEY_PASSWORD_ITERATION, KEY_PASSWORD_PBE_ALGORITHM, KEY_PASSWORD_PBE_INITIAL_KEY,
                KEY_SIZE, CRYPTO_ALGORITHM, RELOADABLE);
    }

    private boolean reloadable = false;
    private File storageFile = null;
    private String vaultName = null;
    private char[] storagePassword = null;
    private String adminKeyAlias = null;
    private boolean initialized = false;
    private SecretKey adminKey = null;
    private int keySize = 128;
    private String cryptoAlgorithm = "AES";
    private boolean createStorage = false;

    private KeyStore.ProtectionParameter adminKeyProtectionParam = null;

    private ConcurrentHashMap<String, byte[]> vault = new ConcurrentHashMap<>();

    /**
     * Default ElytronVaultConstructor.
     */
    public ElytronVault() {
    }

    @Override
    public String getVaultType() {
        return "ElytronVault";
    }

    @Override
    public void init(Map<String, Object> options) throws VaultException {
        checkValidOptions(options.keySet());

        storageFile = new File((String) options.get(STORAGE_FILE));
        vaultName = (String) options.get(NAME);
        storagePassword = convertPassword(options.get(STORAGE_PASSWORD));
        adminKeyAlias = (String) options.get(KEY_ALIAS);
        if (adminKeyAlias == null) {
            adminKeyAlias = DEFAULT_ADMIN_KEY_ALIAS;
        }

        if (options.get(KEY_SIZE) != null) {
            keySize = Integer.parseInt((String) options.get(KEY_SIZE));
        }

        if (options.get(CRYPTO_ALGORITHM) != null) {
            cryptoAlgorithm = (String) options.get(CRYPTO_ALGORITHM);
        }

        if (options.get(CREATE_STORAGE) != null) {
            createStorage = Boolean.parseBoolean((String) options.get(CREATE_STORAGE));
        }

        char[] adminKeyPassword = loadKeyPassword(options);
        if (adminKeyPassword != null) {
            adminKeyProtectionParam = new KeyStore.PasswordProtection(adminKeyPassword);
            destroyPassword(adminKeyPassword);
        }

        readVaultKeyStore();

        initialized = true;
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

    @Override
    public Set<String> getAttributes() {
        if (!isInitialized()) {
            log.vaultIsNotInitialized(vaultName);
        }
        return vault.keySet();
    }

    @Override
    public boolean exists(String attribute) {
        if (!isInitialized()) {
            log.vaultIsNotInitialized(vaultName);
        }
        return vault.containsKey(attribute);
    }

    @Override
    public void store(String attribute, char[] value) throws VaultException {
        if (!isInitialized()) {
            log.vaultIsNotInitialized(vaultName);
        }
        if (!reloadable) {
            try {
                vault.put(attribute, encryptEntry(value, null));
            } catch (GeneralSecurityException e) {
                throw log.vaultException(e);
            }
            storeToFile();
        } else {
            throw log.reloadableVaultIsReadOnly(vaultName);
        }
    }

    @Override
    public char[] retrieve(String attribute) throws VaultException {
        if (!isInitialized()) {
            log.vaultIsNotInitialized(vaultName);
        }

        byte[] encryptedAttribute = vault.get(attribute);
        if (encryptedAttribute == null) {
            throw log.securedAttributeNotFound(attribute, vaultName);
        }

        try {
            return decryptEntry(encryptedAttribute, null);
        } catch (GeneralSecurityException e) {
            throw log.vaultException(e);
        }
    }

    @Override
    public void remove(String attribute) throws VaultException {
        if (!isInitialized()) {
            log.vaultIsNotInitialized(vaultName);
        }
        vault.remove(attribute);
    }

    private synchronized void storeToFile() throws VaultException {

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
            throw log.vaultException(e);
        }
    }

    private void packToKeyStore(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException {
        // adminKey handling
        keyStore.setEntry(adminKeyAlias, new KeyStore.SecretKeyEntry(adminKey), adminKeyProtectionParam);
        // secret attributes
        final PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Set<String> vaultAttributes = vault.keySet();
        for (String attribute : vaultAttributes) {
            ClearPassword password = (ClearPassword)passwordFactory.generatePassword(new ClearPasswordSpec(byteArrayDecode(vault.get(attribute))));
            keyStore.setEntry(attribute, new KeyStore.SecretKeyEntry(wrapPassword(password)), adminKeyProtectionParam);
        }
    }

    private void checkValidOptions(Set<String> options) throws VaultException {
        StringBuilder wrongOptions = new StringBuilder();
        for (String o : options) {
            if (!o.startsWith(KEY_PASSWORD_CALLBACK) && !supportedOptions.contains(o)) {
                wrongOptions.append(", ").append(o);
            }
        }
        if (wrongOptions.length() > 0) {
            throw log.unsuportedVaultOption(wrongOptions.substring(2));
        }
    }

    private void readVaultKeyStore() throws VaultException {

        if (createStorage && (!storageFile.exists() || !storageFile.canRead())) {
            // do not read key store, just generate adminKey
            try {
                adminKey = generateSecretKey();
            } catch (NoSuchAlgorithmException e) {
                throw log.vaultException(e);
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
                    vault.put(alias, secret.getSecretKey().getEncoded());
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
        KeyGenerator generator = KeyGenerator.getInstance(cryptoAlgorithm);
        generator.init(keySize);
        return generator.generateKey();
    }


    /**
     * Encrypt {@code entry} by encoding it using UTF-8 to {@code byte[]}
     * {@code char[]} is first encoded to {@code byte[]} using {@link java.nio.charset.StandardCharsets}.UTF_8 character set.
     *
     * @param entry to encrypt
     * @param cipher {@link Cipher} to encrypt the entry
     * @return encrypted value
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     */
    private byte[] encryptEntry(char[] entry, Cipher cipher) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = (cipher != null ? cipher : getCipher(Cipher.ENCRYPT_MODE));
        return c.doFinal(charArrayEncode(entry));
    }

    /**
     * Decrypting secret entry directly to {@code char[]}.
     * {@code byte[]} is encoded to {@code char[]} using {@link java.nio.charset.StandardCharsets}.UTF_8 character set.
     *
     * @param entry to decrypt
     * @param cipher {@link Cipher} to decrypt the entry
     * @return decrypted and UTF-8 char[] encoded value of entry
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private char[] decryptEntry(byte[] entry, Cipher cipher) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = (cipher != null ? cipher : getCipher(Cipher.DECRYPT_MODE));
        return byteArrayDecode(c.doFinal(entry));
    }

    static char[] byteArrayDecode(byte[] buffer) {
        return new String(buffer, StandardCharsets.UTF_8).toCharArray();
    }

    static byte[] charArrayEncode(char[] buffer) {
        return Normalizer.normalize(new String(buffer), Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
    }

    private Cipher getCipher(int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec adminKeySpec = new SecretKeySpec(adminKey.getEncoded(), cryptoAlgorithm);
        Cipher c = Cipher.getInstance(cryptoAlgorithm);
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

    private char[] loadKeyPassword(final Map<String, Object> options) throws VaultException {
        ExternalPasswordLoader passwordLoader = new ExternalPasswordLoader(
                KEY_PASSWORD_CALLBACK,
                KEY_PASSWORD_CALLBACK_HANDLER,
                KEY_PASSWORD_CALLBACK_PASSWORD_CLASS,
                KEY_PASSWORD,
                KEY_PASSWORD_MASKED, KEY_PASSWORD_SALT, KEY_PASSWORD_ITERATION, KEY_PASSWORD_PBE_ALGORITHM, KEY_PASSWORD_PBE_INITIAL_KEY);
        try {
            return passwordLoader.loadPassword(options);
        } catch (IllegalAccessException | InstantiationException | IOException | UnsupportedCallbackException | NoSuchMethodException e) {
            throw new VaultException(e);
        }
    }
}
