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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.common.Assert;
import org.wildfly.security.EmptyProvider;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.PublicKeyCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.key.KeyUtil;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.MaskedPasswordSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.AtomicFileOutputStream;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;
import org.wildfly.security.x500.X500;

/**
 * A flexible credential store which is backed by a key store.  The key store holds the credentials, encoding identifying
 * information into the alias to allow multiple credentials to be stored under each alias (something keystores generally
 * do not support).
 * <p>
 * This credential store cannot convert an arbitrary key store into a credential store; it can only understand entries that
 * it itself has added.  Entries not understood by this credential store will be ignored (and a log message will be
 * generated indicating the presence of unknown credentials).
 * <p>
 * The following configuration parameters are supported:
 * <ul>
 *     <li>{@code location}: specifies the location of the key store (none means, use an in-memory store and do not store changes)</li>
 *     <li>{@code modifiable}: specifies whether the credential store should be modifiable</li>
 *     <li>{@code create}: specifies to automatically create storage file for this credential store (defaults to {@code false}).
 *          <p>
 *          If {@code external} is true, the storage file will be created calling the {@link #flush} method. If {@code external} is false and the storage file does not exist yet,
 *          then an empty credential store is created when {@link #initialize} method is invoked.</li>
 *     <li>{@code keyStoreType}: specifies the key store type to use (defaults to {@link KeyStore#getDefaultType()})</li>
 *     <li>{@code keyAlias}: specifies the secret key alias within the key store to use for encrypt/decrypt of data in external storage (defaults to {@code cs_key})</li>
 *     <li>{@code external}: specifies whether to store data to external storage and encrypted by {@code keyAlias} key (defaults to {@code false})</li>
 *     <li>{@code externalPath}: specifies path to the external storage. It has to be used in conjunction with {@code external=true} and it defaults to value of {@code location} when {@code keyStoreType} is PKCS11.</li>
 *     <li>{@code cryptoAlg}: cryptographic algorithm name to be used to encrypt decrypt entries at external storage ({@code external} has to be set to {@code true})</li>
 * </ul>
 */
public final class KeyStoreCredentialStore extends CredentialStoreSpi {

    private static final String DATA_OID = "1.2.840.113549.1.7.1";

    /**
     * The name of this credential store implementation.
     */
    public static final String KEY_STORE_CREDENTIAL_STORE = KeyStoreCredentialStore.class.getSimpleName();

    private static final String X_509 = "X.509";
    private static final String CREATE = "create";
    private static final String CRYPTOALG = "cryptoAlg";
    private static final String EXTERNAL = "external";
    private static final String EXTERNALPATH = "externalPath";
    private static final String KEYALIAS = "keyAlias";
    private static final String KEYSTORETYPE = "keyStoreType";
    private static final String LOCATION = "location";
    private static final String MODIFIABLE = "modifiable";

    private static final List<String> validAttribtues = Arrays.asList(CREATE, CRYPTOALG, EXTERNAL, EXTERNALPATH, KEYALIAS,
            KEYSTORETYPE, LOCATION, MODIFIABLE);

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final HashMap<String, TopEntry> cache = new HashMap<>();
    private volatile boolean modifiable;
    private KeyStore keyStore;
    private Path location;
    private Path externalPath;
    private boolean create;
    private CredentialStore.ProtectionParameter protectionParameter;
    private Provider[] providers;
    private String encryptionKeyAlias;
    private boolean useExternalStorage = false;
    private ExternalStorage externalStorage;
    private String cryptographicAlgorithm;

    public void initialize(final Map<String, String> attributes, final CredentialStore.ProtectionParameter protectionParameter, final Provider[] providers) throws CredentialStoreException {
        try (Hold hold = lockForWrite()) {
            if (protectionParameter == null) {
                throw log.protectionParameterRequired();
            }
            validateAttribute(attributes, validAttribtues);
            cache.clear();
            this.protectionParameter = protectionParameter;
            modifiable = Boolean.parseBoolean(attributes.getOrDefault(MODIFIABLE, "true"));
            create = Boolean.parseBoolean(attributes.getOrDefault(CREATE, "false"));
            final String locationName = attributes.get(LOCATION);
            location = locationName == null ? null : Paths.get(locationName);
            this.providers = providers;
            String keyStoreType = attributes.getOrDefault(KEYSTORETYPE, KeyStore.getDefaultType());
            useExternalStorage = Boolean.parseBoolean(attributes.getOrDefault(EXTERNAL, "false"));
            if (useExternalStorage) {
                final String externalPathName = attributes.get(EXTERNALPATH);
                if (externalPathName == null) {
                    externalPath = location;
                    location = null;
                } else {
                    externalPath = Paths.get(externalPathName);
                    if (externalPath.equals(location)) {
                        throw log.locationAndExternalPathAreIdentical(location.toString(), externalPath.toString());
                    }
                }
            }
            encryptionKeyAlias = attributes.getOrDefault(KEYALIAS, "cs_key");
            cryptographicAlgorithm = attributes.get(CRYPTOALG);
            load(keyStoreType);
            if ( create  && !useExternalStorage && location != null && !Files.exists(location) ){
                //Only in this case, flush the data to the file allowing the credential store creation independently of modifiable flag
                flush();
            }
            initialized = true;
        }
    }

    public boolean isModifiable() {
        return modifiable;
    }

    public void store(final String credentialAlias, final Credential credential, final CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        try {
            // first, attempt to encode the credential into a keystore entry
            final Class<? extends Credential> credentialClass = credential.getClass();
            final String algorithmName = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getAlgorithm() : null;
            final AlgorithmParameterSpec parameterSpec = credential.castAndApply(AlgorithmCredential.class, AlgorithmCredential::getParameters);
            final KeyStore.Entry entry;
            if (credentialClass == SecretKeyCredential.class) {
                entry = new KeyStore.SecretKeyEntry(credential.castAndApply(SecretKeyCredential.class, SecretKeyCredential::getSecretKey));
            } else if (credentialClass == PublicKeyCredential.class) {
                final PublicKey publicKey = credential.castAndApply(PublicKeyCredential.class, PublicKeyCredential::getPublicKey);
                final KeyFactory keyFactory = KeyFactory.getInstance(publicKey.getAlgorithm());
                final X509EncodedKeySpec keySpec = keyFactory.getKeySpec(keyFactory.translateKey(publicKey), X509EncodedKeySpec.class);
                final byte[] encoded = keySpec.getEncoded();
                entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(encoded, DATA_OID));
            } else if (credentialClass == KeyPairCredential.class) {
                final KeyPair keyPair = credential.castAndApply(KeyPairCredential.class, KeyPairCredential::getKeyPair);
                final PublicKey publicKey = keyPair.getPublic();
                final PrivateKey privateKey = keyPair.getPrivate();
                final KeyFactory keyFactory = KeyFactory.getInstance(publicKey.getAlgorithm());
                // ensured by KeyPairCredential
                assert privateKey.getAlgorithm().equals(publicKey.getAlgorithm());
                final X509EncodedKeySpec publicSpec = keyFactory.getKeySpec(keyFactory.translateKey(publicKey), X509EncodedKeySpec.class);
                final PKCS8EncodedKeySpec privateSpec = keyFactory.getKeySpec(keyFactory.translateKey(privateKey), PKCS8EncodedKeySpec.class);
                final DEREncoder encoder = new DEREncoder();
                encoder.startSequence();
                encoder.writeEncoded(publicSpec.getEncoded());
                encoder.writeEncoded(privateSpec.getEncoded());
                encoder.endSequence();
                entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(encoder.getEncoded(), DATA_OID));
            } else if (credentialClass == X509CertificateChainPublicCredential.class) {
                final X509Certificate[] x509Certificates = credential.castAndApply(X509CertificateChainPublicCredential.class, X509CertificateChainPublicCredential::getCertificateChain);
                final DEREncoder encoder = new DEREncoder();
                encoder.encodeInteger(x509Certificates.length);
                encoder.startSequence();
                for (X509Certificate x509Certificate : x509Certificates) {
                    encoder.writeEncoded(x509Certificate.getEncoded());
                }
                encoder.endSequence();
                entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(encoder.getEncoded(), DATA_OID));
            } else if (credentialClass == X509CertificateChainPrivateCredential.class) {
                @SuppressWarnings("ConstantConditions")
                X509CertificateChainPrivateCredential cred = (X509CertificateChainPrivateCredential) credential;
                entry = new KeyStore.PrivateKeyEntry(cred.getPrivateKey(), cred.getCertificateChain());
            } else if (credentialClass == BearerTokenCredential.class) {
                entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(credential.castAndApply(BearerTokenCredential.class, c -> c.getToken().getBytes(StandardCharsets.UTF_8)), DATA_OID));
            } else if (credentialClass == PasswordCredential.class) {
                final Password password = credential.castAndApply(PasswordCredential.class, PasswordCredential::getPassword);
                final String algorithm = password.getAlgorithm();
                final DEREncoder encoder = new DEREncoder();
                final PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
                switch (algorithm) {
                    case BCryptPassword.ALGORITHM_BCRYPT:
                    case BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES:
                    case ScramDigestPassword.ALGORITHM_SCRAM_SHA_1:
                    case ScramDigestPassword.ALGORITHM_SCRAM_SHA_256:
                    case ScramDigestPassword.ALGORITHM_SCRAM_SHA_384:
                    case ScramDigestPassword.ALGORITHM_SCRAM_SHA_512:
                    case SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5:
                    case SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5_BARE_SALT:
                    case UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_256:
                    case UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_512: {
                        IteratedSaltedHashPasswordSpec passwordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), IteratedSaltedHashPasswordSpec.class);
                        encoder.startSequence();
                        encoder.encodeOctetString(passwordSpec.getHash());
                        encoder.encodeOctetString(passwordSpec.getSalt());
                        encoder.encodeInteger(passwordSpec.getIterationCount());
                        encoder.endSequence();
                        break;
                    }
                    case ClearPassword.ALGORITHM_CLEAR: {
                        final ClearPasswordSpec passwordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), ClearPasswordSpec.class);
                        encoder.encodeOctetString(new String(passwordSpec.getEncodedPassword()));
                        break;
                    }
                    case DigestPassword.ALGORITHM_DIGEST_MD5:
                    case DigestPassword.ALGORITHM_DIGEST_SHA:
                    case DigestPassword.ALGORITHM_DIGEST_SHA_256:
                    case DigestPassword.ALGORITHM_DIGEST_SHA_384:
                    case DigestPassword.ALGORITHM_DIGEST_SHA_512: {
                        final DigestPasswordSpec passwordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), DigestPasswordSpec.class);
                        encoder.startSequence();
                        encoder.encodeOctetString(passwordSpec.getUsername());
                        encoder.encodeOctetString(passwordSpec.getRealm());
                        encoder.encodeOctetString(passwordSpec.getDigest());
                        encoder.endSequence();
                        break;
                    }
                    case OneTimePassword.ALGORITHM_OTP_MD5:
                    case OneTimePassword.ALGORITHM_OTP_SHA1:
                    case OneTimePassword.ALGORITHM_OTP_SHA_256:
                    case OneTimePassword.ALGORITHM_OTP_SHA_384:
                    case OneTimePassword.ALGORITHM_OTP_SHA_512: {
                        final OneTimePasswordSpec passwordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), OneTimePasswordSpec.class);
                        encoder.startSequence();
                        encoder.encodeOctetString(passwordSpec.getHash());
                        encoder.encodeIA5String(passwordSpec.getSeed());
                        encoder.encodeInteger(passwordSpec.getSequenceNumber());
                        encoder.endSequence();
                        break;
                    }
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512:
                    case UnixDESCryptPassword.ALGORITHM_CRYPT_DES:
                    case UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5: {
                        final SaltedHashPasswordSpec passwordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), SaltedHashPasswordSpec.class);
                        encoder.startSequence();
                        encoder.encodeOctetString(passwordSpec.getHash());
                        encoder.encodeOctetString(passwordSpec.getSalt());
                        encoder.endSequence();
                        break;
                    }
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD2:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                        final HashPasswordSpec passwordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), HashPasswordSpec.class);
                        encoder.startSequence();
                        encoder.encodeOctetString(passwordSpec.getDigest());
                        encoder.endSequence();
                        break;
                    }
                    default: {
                        if (MaskedPassword.isMaskedAlgorithm(algorithmName)) {
                            final MaskedPasswordSpec passwordSpec = passwordFactory.getKeySpec(passwordFactory.translate(password), MaskedPasswordSpec.class);
                            encoder.startSequence();
                            encoder.encodeOctetString(new String(passwordSpec.getInitialKeyMaterial()));
                            encoder.encodeInteger(passwordSpec.getIterationCount());
                            encoder.encodeOctetString(passwordSpec.getSalt());
                            encoder.encodeOctetString(passwordSpec.getMaskedPasswordBytes());
                            encoder.endSequence();
                            break;
                        } else {
                            throw log.unsupportedCredentialType(credentialClass);
                        }
                    }
                }
                entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(encoder.getEncoded(), DATA_OID));
            } else {
                throw log.unsupportedCredentialType(credentialClass);
            }
            // now, store it under a unique alias
            final String ksAlias = calculateNewAlias(credentialAlias, credentialClass, algorithmName, parameterSpec);
            try (Hold hold = lockForWrite()) {
                keyStore.setEntry(ksAlias, entry, convertParameter(protectionParameter));
                final TopEntry topEntry = cache.computeIfAbsent(toLowercase(credentialAlias), TopEntry::new);
                final MidEntry midEntry = topEntry.getMap().computeIfAbsent(credentialClass, c -> new MidEntry(topEntry, c));
                final BottomEntry bottomEntry;
                if (algorithmName != null) {
                    bottomEntry = midEntry.getMap().computeIfAbsent(algorithmName, n -> new BottomEntry(midEntry, n));
                } else {
                    bottomEntry = midEntry.getOrCreateNoAlgorithm();
                }
                final String oldAlias;
                if (parameterSpec != null) {
                    oldAlias = bottomEntry.getMap().put(new ParamKey(parameterSpec), ksAlias);
                } else {
                    oldAlias = bottomEntry.setNoParams(ksAlias);
                }
                if (oldAlias != null && ! oldAlias.equals(ksAlias)) {
                    // unlikely but possible
                    keyStore.deleteEntry(oldAlias);
                }
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | CertificateException e) {
            throw log.cannotWriteCredentialToStore(e);
        }
    }

    public <C extends Credential> C retrieve(final String credentialAlias, final Class<C> credentialType, final String credentialAlgorithm, final AlgorithmParameterSpec parameterSpec, final CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        final KeyStore.Entry entry;
        final MidEntry midEntry;
        final BottomEntry bottomEntry;
        final String ksAlias;
        try (Hold hold = lockForRead()) {
            final TopEntry topEntry = cache.get(toLowercase(credentialAlias));
            if (topEntry == null) {
                log.trace("KeyStoreCredentialStore: alias not found in cache");
                return null;
            }
            if (topEntry.getMap().containsKey(credentialType)) {
                log.trace("KeyStoreCredentialStore: contains exact type");
                midEntry = topEntry.getMap().get(credentialType);
            } else {
                // loose (slow) match
                final Iterator<MidEntry> iterator = topEntry.getMap().values().iterator();
                for (;;) {
                    if (! iterator.hasNext()) {
                        log.trace("KeyStoreCredentialStore: no assignable found");
                        return null;
                    }
                    MidEntry item = iterator.next();
                    if (credentialType.isAssignableFrom(item.getCredentialType())) {
                        log.trace("KeyStoreCredentialStore: assignable found");
                        midEntry = item;
                        break;
                    }
                }
            }
            if (credentialAlgorithm != null) {
                bottomEntry = midEntry.getMap().get(credentialAlgorithm);
            } else {
                // match any
                final Iterator<BottomEntry> iterator = midEntry.getMap().values().iterator();
                if (iterator.hasNext()) {
                    bottomEntry = iterator.next();
                } else {
                    bottomEntry = midEntry.getNoAlgorithm();
                }
            }
            if (bottomEntry == null) {
                log.tracef("KeyStoreCredentialStore: no entry for algorithm %s", credentialAlgorithm);
                return null;
            }
            if (parameterSpec != null) {
                ksAlias = bottomEntry.getMap().get(new ParamKey(parameterSpec));
            } else {
                // match any
                final Iterator<String> iterator = bottomEntry.getMap().values().iterator();
                if (iterator.hasNext()) {
                    ksAlias = iterator.next();
                } else {
                    ksAlias = bottomEntry.getNoParams();
                }
            }
            if (ksAlias == null) {
                log.tracef("KeyStoreCredentialStore: no entry for parameterSpec %s", parameterSpec);
                return null;
            }
            entry = keyStore.getEntry(ksAlias, convertParameter(protectionParameter));
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw log.cannotAcquireCredentialFromStore(e);
        }
        if (entry == null) {
            // odd, but we can handle it
            log.trace("KeyStoreCredentialStore: null entry");
            return null;
        }
        final Class<? extends Credential> matchedCredentialType = midEntry.getCredentialType();
        if (matchedCredentialType == SecretKeyCredential.class) {
            if (entry instanceof KeyStore.SecretKeyEntry) {
                // simple
                final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                return credentialType.cast(new SecretKeyCredential(secretKey));
            } else {
                throw log.invalidCredentialStoreEntryType(KeyStore.SecretKeyEntry.class, entry.getClass());
            }
        } else if (matchedCredentialType == PublicKeyCredential.class) {
            if (entry instanceof KeyStore.SecretKeyEntry) try {
                // we store as a secret key because we can't store the public key properly...
                final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                final byte[] encoded = secretKey.getEncoded();
                final String matchedAlgorithm = bottomEntry.getAlgorithm();
                assert matchedAlgorithm != null; // because PublicKeyCredential is an AlgorithmCredential
                final KeyFactory keyFactory = KeyFactory.getInstance(matchedAlgorithm);
                final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
                return credentialType.cast(new PublicKeyCredential(publicKey));
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                throw log.cannotAcquireCredentialFromStore(e);
            } else {
                throw log.invalidCredentialStoreEntryType(KeyStore.SecretKeyEntry.class, entry.getClass());
            }
        } else if (matchedCredentialType == KeyPairCredential.class) {
            if (entry instanceof KeyStore.SecretKeyEntry) try {
                final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                final byte[] encoded = secretKey.getEncoded();
                final String matchedAlgorithm = bottomEntry.getAlgorithm();
                assert matchedAlgorithm != null; // because KeyPairCredential is an AlgorithmCredential
                // extract public and private segments
                final DERDecoder decoder = new DERDecoder(encoded);
                decoder.startSequence();
                final byte[] publicBytes = decoder.drainElement();
                final byte[] privateBytes = decoder.drainElement();
                decoder.endSequence();
                final KeyFactory keyFactory = KeyFactory.getInstance(matchedAlgorithm);
                final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));
                final PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
                final KeyPair keyPair = new KeyPair(publicKey, privateKey);
                return credentialType.cast(new KeyPairCredential(keyPair));
            } catch (InvalidKeySpecException | NoSuchAlgorithmException | ASN1Exception e) {
                throw log.cannotAcquireCredentialFromStore(e);
            } else {
                throw log.invalidCredentialStoreEntryType(KeyStore.SecretKeyEntry.class, entry.getClass());
            }
        } else if (matchedCredentialType == X509CertificateChainPublicCredential.class) {
            if (entry instanceof KeyStore.SecretKeyEntry) try {
                // OK so this is pretty ugly, but the TrustedCertificateEntry type only holds a single cert so it's no good
                final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                final byte[] encoded = secretKey.getEncoded();
                final String matchedAlgorithm = bottomEntry.getAlgorithm();
                assert matchedAlgorithm != null; // because it is an AlgorithmCredential
                final DERDecoder decoder = new DERDecoder(encoded);
                final CertificateFactory certificateFactory = CertificateFactory.getInstance(X_509);
                final int count = decoder.decodeInteger().intValueExact();
                final X509Certificate[] array = new X509Certificate[count];
                decoder.startSequence();
                int i = 0;
                while (decoder.hasNextElement()) {
                    final byte[] certBytes = decoder.drainElement();
                    array[i ++] = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
                }
                decoder.endSequence();
                return credentialType.cast(new X509CertificateChainPublicCredential(array));
            } catch (ASN1Exception | CertificateException | ArrayIndexOutOfBoundsException e) {
                throw log.cannotAcquireCredentialFromStore(e);
            } else {
                throw log.invalidCredentialStoreEntryType(KeyStore.SecretKeyEntry.class, entry.getClass());
            }
        } else if (matchedCredentialType == X509CertificateChainPrivateCredential.class) {
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                // an entry type that matches our credential type!
                final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
                final PrivateKey privateKey = privateKeyEntry.getPrivateKey();
                final Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
                final X509Certificate[] x509Certificates = X500.asX509CertificateArray(certificateChain);
                return credentialType.cast(new X509CertificateChainPrivateCredential(privateKey, x509Certificates));
            } else {
                throw log.invalidCredentialStoreEntryType(KeyStore.PrivateKeyEntry.class, entry.getClass());
            }
        } else if (matchedCredentialType == BearerTokenCredential.class) {
            if (entry instanceof KeyStore.SecretKeyEntry) {
                final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                final byte[] encoded = secretKey.getEncoded();
                return credentialType.cast(new BearerTokenCredential(new String(encoded, StandardCharsets.UTF_8)));
            } else {
                throw log.invalidCredentialStoreEntryType(KeyStore.SecretKeyEntry.class, entry.getClass());
            }
        } else if (matchedCredentialType == PasswordCredential.class) {
            if (entry instanceof KeyStore.SecretKeyEntry) try {
                final SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                final byte[] encoded = secretKey.getEncoded();
                final String matchedAlgorithm = bottomEntry.getAlgorithm();
                assert matchedAlgorithm != null; // because it is an AlgorithmCredential
                final DERDecoder decoder = new DERDecoder(encoded);
                // we use algorithm-based encoding rather than a standard that encompasses all password types.
                final PasswordSpec passwordSpec;
                switch (matchedAlgorithm) {
                    case BCryptPassword.ALGORITHM_BCRYPT:
                    case BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES:
                    case ScramDigestPassword.ALGORITHM_SCRAM_SHA_1:
                    case ScramDigestPassword.ALGORITHM_SCRAM_SHA_256:
                    case ScramDigestPassword.ALGORITHM_SCRAM_SHA_384:
                    case ScramDigestPassword.ALGORITHM_SCRAM_SHA_512:
                    case SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5:
                    case SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5_BARE_SALT:
                    case UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_256:
                    case UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_512: {
                        decoder.startSequence();
                        final byte[] hash = decoder.decodeOctetString();
                        final byte[] salt = decoder.decodeOctetString();
                        final int iterationCount = decoder.decodeInteger().intValue();
                        decoder.endSequence();
                        passwordSpec = new IteratedSaltedHashPasswordSpec(hash, salt, iterationCount);
                        break;
                    }
                    case ClearPassword.ALGORITHM_CLEAR: {
                        passwordSpec = new ClearPasswordSpec(decoder.decodeOctetStringAsString().toCharArray());
                        break;
                    }
                    case DigestPassword.ALGORITHM_DIGEST_MD5:
                    case DigestPassword.ALGORITHM_DIGEST_SHA:
                    case DigestPassword.ALGORITHM_DIGEST_SHA_256:
                    case DigestPassword.ALGORITHM_DIGEST_SHA_384:
                    case DigestPassword.ALGORITHM_DIGEST_SHA_512: {
                        decoder.startSequence();
                        final String username = decoder.decodeOctetStringAsString();
                        final String realm = decoder.decodeOctetStringAsString();
                        final byte[] digest = decoder.decodeOctetString();
                        decoder.endSequence();
                        passwordSpec = new DigestPasswordSpec(username, realm, digest);
                        break;
                    }
                    case OneTimePassword.ALGORITHM_OTP_MD5:
                    case OneTimePassword.ALGORITHM_OTP_SHA1:
                    case OneTimePassword.ALGORITHM_OTP_SHA_256:
                    case OneTimePassword.ALGORITHM_OTP_SHA_384:
                    case OneTimePassword.ALGORITHM_OTP_SHA_512: {
                        decoder.startSequence();
                        final byte[] hash = decoder.decodeOctetString();
                        final String seed = decoder.decodeIA5String();
                        final int sequenceNumber = decoder.decodeInteger().intValue();
                        decoder.endSequence();
                        passwordSpec = new OneTimePasswordSpec(hash, seed, sequenceNumber);
                        break;
                    }
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
                    case SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
                    case SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512:
                    case UnixDESCryptPassword.ALGORITHM_CRYPT_DES:
                    case UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5: {
                        decoder.startSequence();
                        final byte[] hash = decoder.decodeOctetString();
                        final byte[] salt = decoder.decodeOctetString();
                        decoder.endSequence();
                        passwordSpec = new SaltedHashPasswordSpec(hash, salt);
                        break;
                    }
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD2:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384:
                    case SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                        decoder.startSequence();
                        final byte[] hash = decoder.decodeOctetString();
                        decoder.endSequence();
                        passwordSpec = new HashPasswordSpec(hash);
                        break;
                    }
                    default: {
                        if (MaskedPassword.isMaskedAlgorithm(matchedAlgorithm)) {
                            decoder.startSequence();
                            final char[] initialKeyMaterial = decoder.decodeOctetStringAsString().toCharArray();
                            final int iterationCount = decoder.decodeInteger().intValue();
                            final byte[] salt = decoder.decodeOctetString();
                            final byte[] maskedPasswordBytes = decoder.decodeOctetString();
                            decoder.endSequence();
                            passwordSpec = new MaskedPasswordSpec(initialKeyMaterial, iterationCount, salt, maskedPasswordBytes);
                            break;
                        } else {
                            throw log.unsupportedCredentialType(credentialType);
                        }
                    }
                }
                PasswordFactory passwordFactory = PasswordFactory.getInstance(matchedAlgorithm);
                final Password password = passwordFactory.generatePassword(passwordSpec);
                return credentialType.cast(new PasswordCredential(password));
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                throw log.cannotAcquireCredentialFromStore(e);
            } else {
                throw log.invalidCredentialStoreEntryType(KeyStore.SecretKeyEntry.class, entry.getClass());
            }
        } else {
            throw log.unableToReadCredentialTypeFromStore(matchedCredentialType);
        }
    }

    private KeyStore.ProtectionParameter convertParameter(final CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        // only one conversion is really possible.
        if (protectionParameter == null) {
            return convertParameter(this.protectionParameter);
        } else if (protectionParameter instanceof CredentialStore.CredentialSourceProtectionParameter) {
            final CredentialSource credentialSource = ((CredentialStore.CredentialSourceProtectionParameter) protectionParameter).getCredentialSource();
            try {
                return credentialSource.applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, p -> new KeyStore.PasswordProtection(p.getPassword())));
            } catch (IOException e) {
                throw log.cannotAcquireCredentialFromStore(e);
            }
        } else {
            throw log.invalidProtectionParameter(protectionParameter);
        }
    }

    public void remove(final String credentialAlias, final Class<? extends Credential> credentialType, final String credentialAlgorithm, final AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        String credentialAliasLowerCase = toLowercase(credentialAlias);
        try (Hold hold = lockForWrite()) {
            if (! modifiable) {
                throw log.nonModifiableCredentialStore("remove");
            }
            // unlike retrieve or store, we want to remove *all* matches
            final TopEntry topEntry = cache.get(credentialAliasLowerCase);
            if (topEntry == null) {
                return;
            }
            if (topEntry.getMap().containsKey(credentialType)) {
                remove(topEntry.getMap().remove(credentialType), credentialAlgorithm, parameterSpec);
            } else {
                // loose (slow) match
                Iterator<MidEntry> iterator = topEntry.getMap().values().iterator();
                while (iterator.hasNext()) {
                    final MidEntry item = iterator.next();
                    if (credentialType.isAssignableFrom(item.getCredentialType())) {
                        remove(item, credentialAlgorithm, parameterSpec);
                        if (item.isEmpty()) iterator.remove();
                    }
                }
            }
            cache.remove(credentialAliasLowerCase);
            // done!
        } catch (KeyStoreException e) {
            throw log.cannotRemoveCredentialFromStore(e);
        }
    }

    private void remove(final MidEntry midEntry, final String credentialAlgorithm, final AlgorithmParameterSpec parameterSpec) throws KeyStoreException {
        if (midEntry != null) {
            if (credentialAlgorithm != null) {
                remove(midEntry.getMap().get(credentialAlgorithm), parameterSpec);
            } else {
                // match any
                Iterator<BottomEntry> iterator = midEntry.getMap().values().iterator();
                while (iterator.hasNext()) {
                    final BottomEntry item = iterator.next();
                    remove(item, parameterSpec);
                    if (item.isEmpty()) iterator.remove();
                }
                remove(midEntry.removeNoAlgorithm(), parameterSpec);
            }
            // done!
        }
    }

    private void remove(final BottomEntry bottomEntry, final AlgorithmParameterSpec parameterSpec) throws KeyStoreException {
        if (bottomEntry != null) {
            if (parameterSpec != null) {
                remove(bottomEntry.getMap().remove(new ParamKey(parameterSpec)));
            } else {
                // match any
                Iterator<String> iterator = bottomEntry.getMap().values().iterator();
                while (iterator.hasNext()) {
                    final String item = iterator.next();
                    remove(item);
                    iterator.remove();
                }
                remove(bottomEntry.removeNoParams());
            }
        }
    }

    private void remove(final String ksAlias) throws KeyStoreException {
        if (ksAlias != null) {
            keyStore.deleteEntry(ksAlias);
        }
    }

    public void flush() throws CredentialStoreException {
        try (Hold hold = lockForWrite()) {
            final Path dataLocation = externalPath == null ? location : externalPath;
            log.tracef("KeyStoreCredentialStore: flushing into %s", dataLocation);
            if (dataLocation != null) try {
                final char[] storePassword = getStorePassword(protectionParameter);
                try (AtomicFileOutputStream os = new AtomicFileOutputStream(dataLocation)) {
                    try {
                        if (useExternalStorage) {
                            externalStorage.store(os);
                        } else {
                            keyStore.store(os, storePassword);
                        }
                    } catch (Throwable t) {
                        try {
                            os.cancel();
                        } catch (IOException e) {
                            e.addSuppressed(t);
                            throw e;
                        }
                    }
                }
            } catch (IOException e) {
                throw log.cannotFlushCredentialStore(e);
            }
        }
    }

    /**
     * Returns credential aliases stored in this store as {@code Set<String>}.
     * <p>
     * It is not mandatory to override this method (throws {@link UnsupportedOperationException} by default).
     *
     * @return {@code Set<String>} of all keys stored in this store
     * @throws UnsupportedOperationException when this method is not supported by the underlying credential store
     * @throws CredentialStoreException      if there is any problem with internal store
     */
    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        return cache.keySet();
    }

    private Hold lockForRead() {
        readWriteLock.readLock().lock();
        return () -> readWriteLock.readLock().unlock();
    }

    private Hold lockForWrite() {
        readWriteLock.writeLock().lock();
        return () -> readWriteLock.writeLock().unlock();
    }

    private static final Pattern INDEX_PATTERN = Pattern.compile("(.+)/([a-z0-9_]+)/([-a-z0-9_]+)?/([2-7a-z]+)?$");

    private void load(String type) throws CredentialStoreException {
        // lock held
        final Enumeration<String> enumeration;
        // load the KeyStore from file
        final Path dataLocation;
        if (useExternalStorage) {
            dataLocation = externalPath;
            setupExternalStorage(type, location);
        } else {
            dataLocation = location;
            keyStore = getKeyStoreInstance(type);
        }
        if (create) {
            log.tracef("KeyStoreCredentialStore: creating empty backing KeyStore  dataLocation = %s  external = %b", dataLocation, useExternalStorage);
            if (dataLocation == null) {
                try {
                    keyStore.load(null, null);
                } catch (CertificateException | IOException | NoSuchAlgorithmException e) {
                    throw log.cannotInitializeCredentialStore(e);
                }
            }
        } else {
            if (dataLocation != null && !Files.exists(dataLocation)) {
                throw log.automaticStorageCreationDisabled(dataLocation.toString());
            }
        }

        try {
            if (dataLocation != null && Files.exists(dataLocation)) {
                log.tracef("KeyStoreCredentialStore: loading backing KeyStore %s  external = %b", dataLocation, useExternalStorage);
                char[] password = getStorePassword(protectionParameter);
                try (InputStream fileStream = Files.newInputStream(dataLocation)) {
                    if (useExternalStorage) {
                        externalStorage.load(fileStream);
                    } else {
                        keyStore.load(fileStream, password);
                    }
                }
                enumeration = keyStore.aliases();
            } else {
                keyStore.load(null, null);
                enumeration = Collections.emptyEnumeration();
            }
        } catch (GeneralSecurityException e) {
            throw log.cannotInitializeCredentialStore(
                    log.internalEncryptionProblem(e, dataLocation != null ? dataLocation.toString() : "null"));
        } catch (IOException e) {
            throw log.cannotInitializeCredentialStore(e);
        }

        Matcher matcher;
        while (enumeration.hasMoreElements()) {
            final String ksAlias = enumeration.nextElement().toLowerCase(Locale.ROOT);
            try {
                matcher = INDEX_PATTERN.matcher(ksAlias);
                if (matcher.matches()) {
                    final String alias = matcher.group(1); // required
                    final String credTypeName = matcher.group(2); // required
                    final String algName = matcher.group(3); // may be null if not given
                    final String parameters = matcher.group(4); // null if not given
                    final Class<? extends Credential> credentialType = CREDENTIAL_TYPES.get(credTypeName);
                    if (credentialType == null) {
                        log.logIgnoredUnrecognizedKeyStoreEntry(ksAlias);
                    } else if (algName != null) {
                        if (parameters != null) {
                            byte[] encodedParameters = CodePointIterator.ofString(parameters).base32Decode(Alphabet.Base32Alphabet.LOWERCASE, false).drain();
                            final AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(algName);
                            algorithmParameters.init(encodedParameters);
                            final AlgorithmParameterSpec parameterSpec = algorithmParameters.getParameterSpec(AlgorithmParameterSpec.class);
                            final TopEntry topEntry = cache.computeIfAbsent(alias, TopEntry::new);
                            final MidEntry midEntry = topEntry.getMap().computeIfAbsent(credentialType, k -> new MidEntry(topEntry, k));
                            final BottomEntry bottomEntry = midEntry.getMap().computeIfAbsent(algName, k -> new BottomEntry(midEntry, k));
                            bottomEntry.getMap().put(new ParamKey(parameterSpec), ksAlias);
                        } else {
                            // algorithm but no parameters
                            final TopEntry topEntry = cache.computeIfAbsent(alias, TopEntry::new);
                            final MidEntry midEntry = topEntry.getMap().computeIfAbsent(credentialType, k -> new MidEntry(topEntry, k));
                            final BottomEntry bottomEntry = midEntry.getMap().computeIfAbsent(algName, k -> new BottomEntry(midEntry, k));
                            bottomEntry.setNoParams(ksAlias);
                        }
                    } else {
                        // no algorithm, no parameters
                        final TopEntry topEntry = cache.computeIfAbsent(alias, TopEntry::new);
                        final MidEntry midEntry = topEntry.getMap().computeIfAbsent(credentialType, k -> new MidEntry(topEntry, k));
                        final BottomEntry bottomEntry = midEntry.getOrCreateNoAlgorithm();
                        bottomEntry.setNoParams(ksAlias);
                    }
                } else {
                    log.logIgnoredUnrecognizedKeyStoreEntry(ksAlias);
                }
            } catch (NoSuchAlgorithmException | InvalidParameterSpecException | IOException e) {
                log.logFailedToReadKeyFromKeyStore(e);
            }
        }
    }

    private KeyStore getKeyStoreInstance(String type) throws CredentialStoreException {
        if (providers != null) {
            for (Provider p: providers) {
                try {
                    return KeyStore.getInstance(type, p);
                } catch (KeyStoreException e) {
                    // no such keystore type in provider, ignore
                }
            }
        }
        try {
            if (log.isTraceEnabled()) {
                log.tracef("Obtaining KeyStore instance of type %s, providers: %s", type, Arrays.toString(Security.getProviders()));
            }
            KeyStore ks = KeyStore.getInstance(type);
            log.tracef("Obtained KeyStore instance: %s", ks);
            return ks;
        } catch (KeyStoreException e) {
            throw log.cannotInitializeCredentialStore(e);
        }
    }

    /**
     * Sets {@link #keyStore} to JCEKS type keyStore to be used as external storage.
     * Sets {@link #externalStorage} used to dump/load stored secret data.
     */
    private void setupExternalStorage(final String keyContainingKeyStoreType, final Path keyContainingKeyStoreLocation) throws CredentialStoreException {
        KeyStore keyContainingKeyStore = getKeyStoreInstance(keyContainingKeyStoreType);
        keyStore = getKeyStoreInstance("JCEKS");
        externalStorage = new ExternalStorage();
        try {
            final char[] storePassword = getStorePassword(protectionParameter);
            if (keyContainingKeyStoreLocation != null) {
                try (InputStream is = Files.newInputStream(keyContainingKeyStoreLocation)) {
                    keyContainingKeyStore.load(is, storePassword);
                }
            } else {
                // keystore without file (e.g. PKCS11)
                synchronized (EmptyProvider.getInstance()) {
                    keyContainingKeyStore.load(null, storePassword);
                }
            }
            externalStorage.init(cryptographicAlgorithm, encryptionKeyAlias, keyContainingKeyStore, storePassword, keyStore);
        } catch(IOException | GeneralSecurityException e) {
            throw log.cannotInitializeCredentialStore(e);
        }
    }


    private static final Map<String, Class<? extends Credential>> CREDENTIAL_TYPES;

    static {
        Map<String, Class<? extends Credential>> map = new HashMap<>();
        for (Class<? extends Credential> type : Arrays.asList(
            PasswordCredential.class,
            X509CertificateChainPublicCredential.class,
            X509CertificateChainPrivateCredential.class,
            KeyPairCredential.class,
            PublicKeyCredential.class,
            SecretKeyCredential.class,
            BearerTokenCredential.class
        )) {
            map.put(type.getSimpleName().toLowerCase(Locale.ROOT), type);
        }
        CREDENTIAL_TYPES = map;
    }

    private static char[] getStorePassword(final CredentialStore.ProtectionParameter protectionParameter) throws IOException, CredentialStoreException {
        final char[] password;
        if (protectionParameter instanceof CredentialStore.CredentialSourceProtectionParameter) {
            password = ((CredentialStore.CredentialSourceProtectionParameter) protectionParameter).getCredentialSource().applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        } else if (protectionParameter != null) {
            throw log.invalidProtectionParameter(protectionParameter);
        } else {
            password = null;
        }
        return password;
    }

    interface Hold extends AutoCloseable { void close(); }

    private String calculateNewAlias(String alias, Class<? extends Credential> credentialType, String algorithm, AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        final StringBuilder b = new StringBuilder(64 + alias.length());
        b.append(alias.toLowerCase(Locale.ROOT));
        b.append('/');
        b.append(credentialType.getSimpleName().toLowerCase(Locale.ROOT));
        b.append('/');
        if (algorithm != null) {
            b.append(algorithm.toLowerCase(Locale.ROOT));
            b.append('/');
            if (parameterSpec != null) try {
                final AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(algorithm);
                algorithmParameters.init(parameterSpec);
                ByteIterator.ofBytes(algorithmParameters.getEncoded()).base32Encode(Alphabet.Base32Alphabet.LOWERCASE, false).drainTo(b);
            } catch (NoSuchAlgorithmException | InvalidParameterSpecException | IOException e) {
                throw log.cannotWriteCredentialToStore(e);
            }
        } else {
            b.append('/');
        }
        return b.toString();
    }

    private static String toLowercase(String str) {
        return str.toLowerCase(Locale.ROOT);
    }

    static final class TopEntry {
        private final String alias;
        private final HashMap<Class<? extends Credential>, MidEntry> map = new HashMap<>(0);

        TopEntry(final String alias) {
            this.alias = alias;
        }

        String getAlias() {
            return alias;
        }

        HashMap<Class<? extends Credential>, MidEntry> getMap() {
            return map;
        }
    }

    static final class MidEntry {
        private final TopEntry topEntry;
        private final Class<? extends Credential> credentialType;
        private final HashMap<String, BottomEntry> map = new HashMap<>(0);
        private BottomEntry noAlgorithm;

        MidEntry(final TopEntry topEntry, final Class<? extends Credential> credentialType) {
            this.topEntry = topEntry;
            this.credentialType = credentialType;
        }

        Class<? extends Credential> getCredentialType() {
            return credentialType;
        }

        HashMap<String, BottomEntry> getMap() {
            return map;
        }

        BottomEntry getNoAlgorithm() {
            return noAlgorithm;
        }

        void setNoAlgorithm(final BottomEntry noAlgorithm) {
            this.noAlgorithm = noAlgorithm;
        }

        BottomEntry removeNoAlgorithm() {
            try {
                return noAlgorithm;
            } finally {
                noAlgorithm = null;
            }
        }

        boolean isEmpty() {
            return noAlgorithm == null && map.isEmpty();
        }

        private BottomEntry getOrCreateNoAlgorithm() {
            final BottomEntry noAlgorithm = this.noAlgorithm;
            return noAlgorithm != null ? noAlgorithm : (this.noAlgorithm = new BottomEntry(this, null));
        }
    }

    static final class BottomEntry {
        private final MidEntry midEntry;
        private final String algorithm;
        private final HashMap<ParamKey, String> map = new HashMap<>(0);
        private String noParams;

        BottomEntry(final MidEntry midEntry, final String algorithm) {
            this.midEntry = midEntry;
            this.algorithm = algorithm;
        }

        String getAlgorithm() {
            return algorithm;
        }

        HashMap<ParamKey, String> getMap() {
            return map;
        }

        String getNoParams() {
            return noParams;
        }

        String setNoParams(final String noParams) {
            try {
                return this.noParams;
            } finally {
                this.noParams = noParams;
            }
        }

        boolean isEmpty() {
            return noParams == null && map.isEmpty();
        }

        private String removeNoParams() {
            try {
                return noParams;
            } finally {
                noParams = null;
            }
        }
    }

    static final class ParamKey {
        private final AlgorithmParameterSpec parameterSpec;
        private final int hashCode;

        ParamKey(final AlgorithmParameterSpec parameterSpec) {
            this.parameterSpec = parameterSpec;
            this.hashCode = KeyUtil.parametersHashCode(parameterSpec);
        }

        public int hashCode() {
            return hashCode;
        }

        AlgorithmParameterSpec getParameterSpec() {
            return parameterSpec;
        }

        int getHashCode() {
            return hashCode;
        }
    }

    private final class ExternalStorage {

        // version of external storage file, can be used later to enhance functionality and keep backward compatibility
        private int VERSION = 1;

        private int SECRET_KEY_ENTRY_TYPE = 100;

        private static final String DEFAULT_CRYPTOGRAPHIC_ALGORITHM = "AES/CBC/NoPadding";

        private Cipher encrypt;
        private Cipher decrypt;

        private KeyStore dataKeyStore;
        private KeyStore storageSecretKeyStore;
        private SecretKey storageSecretKey;

        private ExternalStorage() {}

        void init(String cryptographicAlgorithm, String keyAlias, KeyStore keyStore, char[] keyPassword, KeyStore dataKeyStore) throws CredentialStoreException {

            if (cryptographicAlgorithm == null)
                cryptographicAlgorithm = DEFAULT_CRYPTOGRAPHIC_ALGORITHM;

            storageSecretKeyStore = keyStore;
            this.dataKeyStore = dataKeyStore;

            try {
                fetchStorageSecretKey(keyAlias, keyPassword);
                Provider provider = keyStore.getProvider();
                try {
                    encrypt = Cipher.getInstance(cryptographicAlgorithm, provider);
                } catch (NoSuchAlgorithmException e) {
                    // fallback to any provider of desired algorithm
                    encrypt = Cipher.getInstance(cryptographicAlgorithm);
                }
                try {
                    decrypt = Cipher.getInstance(cryptographicAlgorithm, provider);
                } catch (NoSuchAlgorithmException e) {
                    // fallback to any provider of desired algorithm
                    decrypt = Cipher.getInstance(cryptographicAlgorithm);
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | UnrecoverableEntryException |
                    KeyStoreException | IOException | CertificateException e) {
                throw new CredentialStoreException(e);
            }
        }

        private void fetchStorageSecretKey(String keyAlias, char[] keyPassword) throws CertificateException, NoSuchAlgorithmException, IOException, CredentialStoreException, UnrecoverableEntryException, KeyStoreException {
            KeyStore.Entry entry = storageSecretKeyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(keyPassword));
            if (entry == null) {
                throw log.externalStorageKeyDoesNotExist(keyAlias);
            }
            if (! (entry instanceof KeyStore.SecretKeyEntry)) {
                throw log.wrongTypeOfExternalStorageKey(keyAlias);
            }
            storageSecretKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }

        /**
         * Load {@link #dataKeyStore} with data from the input stream.
         *
         * @param inputStream to load data from
         * @throws IOException if something goes wrong
         */
        void load(InputStream inputStream) throws IOException, GeneralSecurityException {
            dataKeyStore.load(null, null);
            ObjectInputStream ois = new ObjectInputStream(inputStream);
            int fileVersion = ois.readInt();
            if (fileVersion == VERSION) {
                while (ois.available() > 0) {
                    int entryType = ois.readInt();
                    if (entryType == SECRET_KEY_ENTRY_TYPE) {
                        loadSecretKey(ois);
                    } else {
                        throw log.unrecognizedEntryType(Integer.toString(entryType));
                    }
                }
            } else {
                throw log.unexpectedFileVersion(Integer.toString(fileVersion));
            }
            ois.close();
        }

        private void loadSecretKey(ObjectInputStream ois) throws IOException, GeneralSecurityException {
            byte[] encryptedData = readBytes(ois);
            byte[] iv = readBytes(ois);

            decrypt.init(Cipher.DECRYPT_MODE, storageSecretKey, new IvParameterSpec(iv));
            Assert.checkMaximumParameter("cipher block size", 256, decrypt.getBlockSize());
            byte[] unPadded = pkcs7UnPad(decrypt.doFinal(encryptedData));
            ObjectInputStream entryOis = new ObjectInputStream(new ByteArrayInputStream(unPadded));
            String ksAlias = entryOis.readUTF();
            byte[] encodedSecretKey = readBytes(entryOis);
            KeyStore.Entry entry = new KeyStore.SecretKeyEntry(new SecretKeySpec(encodedSecretKey, DATA_OID));
            dataKeyStore.setEntry(ksAlias, entry, convertParameter(protectionParameter));
        }

        private byte[] readBytes(ObjectInputStream ois) throws IOException {
            int len = ois.readInt();
            byte[] data = new byte[len];
            int actualLen = ois.read(data, 0, len);
            if (len != actualLen) throw log.readBytesMismatch(actualLen, len);
            return data;
        }

        private int writeBytes(byte[] data, ObjectOutputStream oos) throws IOException {
            int len = data.length;
            oos.writeInt(len);
            oos.write(data, 0, len);
            return len;
        }

        /**
         * Store data from {@link #dataKeyStore} to output stream.
         *
         * @param outputStream to store data to
         * @throws IOException if something goes wrong
         */
        void store(OutputStream outputStream) throws IOException, GeneralSecurityException {
            ObjectOutputStream oos = new ObjectOutputStream(outputStream);
            oos.writeInt(VERSION);
            Enumeration<String> ksAliases = dataKeyStore.aliases();
            while(ksAliases.hasMoreElements()) {
                String alias = ksAliases.nextElement();
                KeyStore.Entry entry = dataKeyStore.getEntry(alias, convertParameter(protectionParameter));
                if (entry instanceof KeyStore.SecretKeyEntry) {
                    saveSecretKey(alias, oos, (KeyStore.SecretKeyEntry)entry);
                } else {
                    throw log.unrecognizedEntryType(entry != null ? entry.getClass().getCanonicalName() : "null");
                }
            }
            oos.flush();
            oos.close();
        }

        private void saveSecretKey(String ksAlias, ObjectOutputStream oos, KeyStore.SecretKeyEntry entry) throws IOException, GeneralSecurityException {
            ByteArrayOutputStream entryData = new ByteArrayOutputStream(1024);
            ObjectOutputStream entryOos = new ObjectOutputStream(entryData);
            entryOos.writeUTF(ksAlias);
            writeBytes(entry.getSecretKey().getEncoded(), entryOos);
            entryOos.flush();

            encrypt.init(Cipher.ENCRYPT_MODE, storageSecretKey, (AlgorithmParameterSpec) null); // ELY-1308: third param need to workaround BouncyCastle bug
            int blockSize = encrypt.getBlockSize();
            if (blockSize == 0) throw log.algorithmNotBlockBased(encrypt.getAlgorithm());
            Assert.checkMaximumParameter("cipher block size", 256, blockSize);
            byte[] padded = pkcs7Pad(entryData.toByteArray(), blockSize);

            byte[] encrypted = encrypt.doFinal(padded);
            byte[] iv = encrypt.getIV();
            if (iv == null) throw log.algorithmNotIV(encrypt.getAlgorithm());

            oos.writeInt(SECRET_KEY_ENTRY_TYPE);
            writeBytes(encrypted, oos);
            writeBytes(iv, oos);
        }

        private byte[] pkcs7Pad(byte[] buffer, int blockSize) {
            int len = buffer.length;
            int toFill = blockSize - (len % blockSize);
            byte[] padded = Arrays.copyOf(buffer, toFill + len);
            Arrays.fill(padded, len, padded.length, (byte) toFill);
            return padded;
        }

        private byte[] pkcs7UnPad(byte[] buffer) throws BadPaddingException {
            byte last = buffer[buffer.length - 1];
            int i = buffer.length - 2;
            while (buffer[i] == last) {
                i--;
            }
            if (i + 1 + last != buffer.length) {
                throw new BadPaddingException();
            }
            return Arrays.copyOfRange(buffer, 0, i + 1);
        }

    }

}
