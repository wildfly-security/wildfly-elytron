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

package org.wildfly.security.password.impl;

import static org.wildfly.common.math.HashMath.multiHashOrdered;
import static org.wildfly.security.password.impl.ElytronMessages.log;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

/**
 * A {@code Password} implementation for {@link SaltedSimpleDigestPassword}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SaltedSimpleDigestPasswordImpl extends AbstractPasswordImpl implements SaltedSimpleDigestPassword {

    private static final long serialVersionUID = -6754143875392946386L;

    private final String algorithm;
    private final byte[] digest;
    private final byte[] salt;

    SaltedSimpleDigestPasswordImpl(final String algorithm, final byte[] salt, final byte[] digest) {
        this.algorithm = algorithm;
        this.digest = digest;
        this.salt = salt;
    }


    SaltedSimpleDigestPasswordImpl(final String algorithm, final SaltedHashPasswordSpec spec) {
        this(algorithm, spec.getSalt().clone(), spec.getHash().clone());
    }

    SaltedSimpleDigestPasswordImpl(final SaltedSimpleDigestPassword password) {
        this(password.getAlgorithm(), password.getSalt().clone(), password.getDigest().clone());
    }

    SaltedSimpleDigestPasswordImpl(final String algorithm, final ClearPasswordSpec spec) throws InvalidKeySpecException {
        this.algorithm = algorithm;
        this.salt = PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE);
        try {
            this.digest = digestOf(algorithm, salt, spec.getEncodedPassword(), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeySpecNoSuchMessageDigestAlgorithm(algorithm);
        }
    }

    SaltedSimpleDigestPasswordImpl(final String algorithm, final char[] password, final SaltedPasswordAlgorithmSpec spec, final Charset hashCharset) throws InvalidKeySpecException {
        this(algorithm, spec.getSalt().clone(), password, hashCharset);
    }

    SaltedSimpleDigestPasswordImpl(final String algorithm, final char[] password, final Charset hashCharset) throws InvalidKeySpecException {
        this(algorithm, PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE), password, hashCharset);
    }

    private SaltedSimpleDigestPasswordImpl(final String algorithm, final byte[] salt, final char[] password, final Charset hashCharset)
            throws InvalidKeySpecException {
        this.algorithm = algorithm;
        this.salt = salt;
        try {
            this.digest = digestOf(algorithm, salt, password, hashCharset);
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeySpecNoSuchMessageDigestAlgorithm(algorithm);
        }
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public byte[] getDigest() {
        return digest.clone();
    }

    @Override
    public byte[] getSalt() {
        return salt.clone();
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(SaltedHashPasswordSpec.class)) {
            return keySpecType.cast(new SaltedHashPasswordSpec(digest.clone(), salt.clone()));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        return verify(guess, StandardCharsets.UTF_8);
    }

    @Override
    boolean verify(char[] guess, Charset hashCharset) throws InvalidKeyException {
        try {
            return MessageDigest.isEqual(digest, digestOf(algorithm, salt, guess, hashCharset));
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeyNoSuchMessageDigestAlgorithm(algorithm);
        }
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(SaltedHashPasswordSpec.class);
    }

    private static byte[] digestOf(final String algorithm, final byte[] salt, final char[] password, final Charset hashCharset)
            throws NoSuchAlgorithmException {
        boolean saltFirst = isSaltFirst(algorithm);
        MessageDigest md = getMessageDigest(algorithm);
        byte[] passwordBytes = new String(password).getBytes(hashCharset);
        if (saltFirst) {
            md.update(salt);
            md.update(passwordBytes);
        } else {
            md.update(passwordBytes);
            md.update(salt);
        }
        return md.digest();
    }

    private static MessageDigest getMessageDigest(final String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
                return MessageDigest.getInstance("MD5");
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
                return MessageDigest.getInstance("SHA-1");
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
                return MessageDigest.getInstance("SHA-256");
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
                return MessageDigest.getInstance("SHA-384");
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512:
                return MessageDigest.getInstance("SHA-512");
            default:
                throw log.noSuchAlgorithmInvalidAlgorithm(algorithm);
        }
    }

    private static boolean isSaltFirst(final String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
                return false;
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512:
                return true;
            default:
                throw log.noSuchAlgorithmInvalidAlgorithm(algorithm);
        }
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(Arrays.hashCode(digest), Arrays.hashCode(salt)), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof SaltedSimpleDigestPasswordImpl)) {
            return false;
        }
        SaltedSimpleDigestPasswordImpl other = (SaltedSimpleDigestPasswordImpl) obj;
        return algorithm.equals(other.algorithm) && MessageDigest.isEqual(digest, other.digest) && Arrays.equals(salt, other.salt);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return SaltedSimpleDigestPassword.createRaw(algorithm, digest, salt);
    }

    public SaltedSimpleDigestPasswordImpl clone() {
        return this;
    }

}
