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

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SaltedSimpleDigestPasswordSpec;

/**
 * A {@link Password} implementation for {@link SaltedSimpleDigestPassword}.
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

    SaltedSimpleDigestPasswordImpl(final SaltedSimpleDigestPasswordSpec spec) {
        this(spec.getAlgorithm(), spec.getSalt().clone(), spec.getDigest().clone());
    }

    SaltedSimpleDigestPasswordImpl(final SaltedSimpleDigestPassword password) {
        this(password.getAlgorithm(), password.getSalt().clone(), password.getDigest().clone());
    }

    SaltedSimpleDigestPasswordImpl(final String algorithm, final ClearPasswordSpec spec) throws InvalidKeySpecException {
        this.algorithm = algorithm;
        this.salt = PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE);
        try {
            this.digest = digestOf(algorithm, salt, spec.getEncodedPassword());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeySpecException("No such MessageDigest algorithm for " + algorithm);
        }
    }

    SaltedSimpleDigestPasswordImpl(final String algorithm, final EncryptablePasswordSpec spec) throws InvalidKeySpecException {
        this(algorithm, spec.getPassword(), (SaltedPasswordAlgorithmSpec) spec.getAlgorithmParameterSpec());
    }

    private SaltedSimpleDigestPasswordImpl(final String algorithm, final char[] password, final SaltedPasswordAlgorithmSpec spec) throws InvalidKeySpecException {
        this(algorithm, spec.getSalt() == null ? PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE) : spec.getSalt().clone(), password);
    }

    private SaltedSimpleDigestPasswordImpl(final String algorithm, final byte[] salt, final char[] password)
            throws InvalidKeySpecException {
        this.algorithm = algorithm;
        this.salt = salt;
        try {
            this.digest = digestOf(algorithm, salt, password);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeySpecException("No such MessageDigest algorithm for " + algorithm);
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
        if (keySpecType.isAssignableFrom(SaltedSimpleDigestPasswordSpec.class)) {
            return keySpecType.cast(new SaltedSimpleDigestPasswordSpec(algorithm, digest.clone(), salt.clone()));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        try {
            return Arrays.equals(digest, digestOf(algorithm, salt, guess));
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("No such MessageDigest algorithm for " + algorithm);
        }
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(SaltedSimpleDigestPasswordSpec.class);
    }

    private static byte[] digestOf(final String algorithm, final byte[] salt, final char[] password)
            throws NoSuchAlgorithmException {
        boolean saltFirst = isSaltFirst(algorithm);
        MessageDigest md = getMessageDigest(algorithm);
        byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
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
                throw new NoSuchAlgorithmException("Invalid algorithm " + algorithm);
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
                throw new NoSuchAlgorithmException("Invalid algorithm " + algorithm);
        }
    }

}
