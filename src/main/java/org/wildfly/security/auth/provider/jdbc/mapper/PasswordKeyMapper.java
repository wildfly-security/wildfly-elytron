/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.provider.jdbc.mapper;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.provider.jdbc.KeyMapper;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.password.spec.ScramDigestPasswordSpec;
import org.wildfly.security.password.spec.SimpleDigestPasswordSpec;
import org.wildfly.security.util.CodePointIterator;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.password.interfaces.BCryptPassword.ALGORITHM_BCRYPT;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_1;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_256;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD2;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5;
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5_BARE_SALT;
import static org.wildfly.security.password.interfaces.UnixDESCryptPassword.ALGORITHM_CRYPT_DES;
import static org.wildfly.security.password.interfaces.UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_256;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_512;

/**
 * <p>A {@link KeyMapper} that knows how to map columns from a SQL query to attributes of specific {@link org.wildfly.security.password.Password} type
 * as defined by the algorithm.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PasswordKeyMapper implements KeyMapper {

    private final int hash;
    private final String algorithm;
    private int salt = -1;
    private int iterationCount = -1;
    private final Class<?> passwordType;

    /**
     * Constructs a new instance.
     *
     * @param algorithm the algorithm that will be used by this mapper to create a specific {@link org.wildfly.security.password.Password} type
     * @param hash the column index from where the password in its clear, hash or encoded form is obtained
     * @throws InvalidKeyException if the given algorithm is not supported by this mapper.
     */
    public PasswordKeyMapper(String algorithm, int hash) throws InvalidKeyException {
        Assert.checkNotNullParam("algorithm", algorithm);
        Assert.checkMinimumParameter("hash", 1, hash);
        this.algorithm = algorithm;
        this.passwordType = toPasswordType(algorithm);
        this.hash = hash;
    }

    /**
     * Constructs a new instance.
     *
     * @param algorithm the algorithm that will be used by this mapper to create a specific {@link org.wildfly.security.password.Password} type
     * @param hash the column index from where the password in its clear, hash or encoded form is obtained
     * @param salt the column index from where the salt, if supported by the given algorithm, is obtained
     * @throws InvalidKeyException if the given algorithm is not supported by this mapper.
     */
    public PasswordKeyMapper(String algorithm, int hash, int salt) throws InvalidKeyException {
        this(algorithm, hash);
        Assert.checkMinimumParameter("salt", 1, salt);
        this.salt = salt;
    }

    /**
     * Constructs a new instance.
     *
     * @param algorithm the algorithm that will be used by this mapper to create a specific {@link org.wildfly.security.password.Password} type
     * @param hash the column index from where the password in its clear, hash or encoded form is obtained
     * @param salt the column index from where the salt, if supported by the given algorithm, is obtained
     * @param iterationCount the column index from where the iteration count or cost, if supported by the given algorithm, is obtained
     * @throws InvalidKeyException if the given algorithm is not supported by this mapper.
     */
    public PasswordKeyMapper(String algorithm, int hash, int salt, int iterationCount) throws InvalidKeyException {
        this(algorithm, hash, salt);
        Assert.checkMinimumParameter("iterationCount", 1, iterationCount);
        this.iterationCount = iterationCount;
    }

    @Override
    public Class<?> getKeyType() {
        return this.passwordType;
    }

    @Override
    public CredentialSupport getCredentialSupport(ResultSet resultSet) {
        Object map = map(resultSet);

        if (map != null) {
            return CredentialSupport.FULLY_SUPPORTED;
        }

        return CredentialSupport.UNSUPPORTED;
    }

    /**
     * Returns the name of the algorithm being used.
     *
     * @return the algorithm
     */
    public String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * Returns an integer representing the column index from where the password in its clear, hash or encoded form is obtained.
     *
     * @return the column index
     */
    public int getHash() {
        return this.hash;
    }

    /**
     * Returns an integer representing the column index from where the salt (if supported) is obtained.
     *
     * @return the column index
     */
    public int getSalt() {
        return this.salt;
    }

    /**
     * Returns an integer representing the column index from where the iteration count (if supported) is obtained.
     *
     * @return the column index
     */
    public int getIterationCount() {
        return this.iterationCount;
    }

    @Override
    public Object map(ResultSet resultSet) {
        byte[] hash = null;
        byte[] salt = null;
        int iterationCount = 0;

        try {
            if (resultSet.next()) {
                hash = toByteArray(resultSet.getObject(getHash()));

                if (getSalt() > 0) {
                    salt = toByteArray(resultSet.getObject(getSalt()));
                }

                if (getIterationCount() > 0) {
                    iterationCount = resultSet.getInt(getIterationCount());
                }
            }
        } catch (SQLException e) {
            throw log.couldNotObtainCredentialWithCause(e);
        }

        if (hash != null) {
            PasswordFactory passwordFactory = getPasswordFactory(getAlgorithm());

            try {
                Class<?> credentialType = getKeyType();

                if (ClearPassword.class.equals(credentialType)) {
                    return toClearPassword(hash, passwordFactory);
                } else if (BCryptPassword.class.equals(credentialType)) {
                    return PasswordUtil.parseCryptString(toCharArray(hash));
                } else if (SaltedSimpleDigestPassword.class.equals(credentialType)) {
                    return toSaltedSimpleDigestPassword(hash, salt, passwordFactory);
                } else if (SimpleDigestPassword.class.equals(credentialType)) {
                    return toSimpleDigestPassword(hash, passwordFactory);
                } else if (ScramDigestPassword.class.equals(credentialType)) {
                    return toScramDigestPassword(hash, salt, iterationCount, passwordFactory);
                }
            } catch (InvalidKeySpecException e) {
                throw log.invalidPasswordKeySpecificationForAlgorithm(algorithm, e);
            }
        }

        return null;
    }

    private Object toScramDigestPassword(byte[] hash, byte[] salt, int iterationCount, PasswordFactory passwordFactory) throws InvalidKeySpecException {
        if (salt == null) {
            throw log.saltIsExpectedWhenCreatingPasswords(ScramDigestPassword.class.getSimpleName());
        }

        ScramDigestPasswordSpec saltedSimpleDigestPasswordSpec = new ScramDigestPasswordSpec(hash, salt, iterationCount);
        return passwordFactory.generatePassword(saltedSimpleDigestPasswordSpec);
    }

    private Object toSimpleDigestPassword(byte[] hash, PasswordFactory passwordFactory) throws InvalidKeySpecException {
        SimpleDigestPasswordSpec simpleDigestPasswordSpec = new SimpleDigestPasswordSpec(hash);
        return passwordFactory.generatePassword(simpleDigestPasswordSpec);
    }

    private Object toSaltedSimpleDigestPassword(byte[] hash, byte[] salt, PasswordFactory passwordFactory) throws InvalidKeySpecException {
        if (salt == null) {
            throw log.saltIsExpectedWhenCreatingPasswords(SaltedSimpleDigestPassword.class.getSimpleName());
        }

        SaltedHashPasswordSpec saltedSimpleDigestPasswordSpec = new SaltedHashPasswordSpec(hash, salt);
        return passwordFactory.generatePassword(saltedSimpleDigestPasswordSpec);
    }

    private Object toClearPassword(byte[] hash, PasswordFactory passwordFactory) throws InvalidKeySpecException {
        return passwordFactory.generatePassword(new ClearPasswordSpec(toCharArray(hash)));
    }

    private PasswordFactory getPasswordFactory(String algorithm) {
        try {
            return PasswordFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw log.couldNotObtainPasswordFactoryForAlgorithm(algorithm, e);
        }
    }

    private byte[] toByteArray(Object value) {
        if (String.class.isInstance(value)) {
            return value.toString().getBytes(StandardCharsets.UTF_8);
        } else if (byte[].class.isInstance(value)) {
            return (byte[]) value;
        }

        return new byte[0];
    }

    private char[] toCharArray(byte[] hash) {
        return CodePointIterator.ofUtf8Bytes(hash).drainToString().toCharArray();
    }

    /**
     * TODO: we probably want to reuse this logic. See org.wildfly.security.password.impl.PasswordFactorySpiImpl#engineTranslatePassword(java.lang.String, org.wildfly.security.password.Password).
     */
    private Class<?> toPasswordType(String algorithm) throws InvalidKeyException {
        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                return ClearPassword.class;
            }
            case ALGORITHM_BCRYPT: {
                return BCryptPassword.class;
            }
            case ALGORITHM_CRYPT_MD5: {
                return UnixMD5CryptPassword.class;
            }
            case ALGORITHM_SUN_CRYPT_MD5:
            case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                return SunUnixMD5CryptPassword.class;
            }
            case ALGORITHM_CRYPT_SHA_256:
            case ALGORITHM_CRYPT_SHA_512: {
                return ClearPassword.class;
            }
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_512: {
                return DigestPassword.class;
            }
            case ALGORITHM_SIMPLE_DIGEST_MD2:
            case ALGORITHM_SIMPLE_DIGEST_MD5:
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:
            case ALGORITHM_SIMPLE_DIGEST_SHA_256:
            case ALGORITHM_SIMPLE_DIGEST_SHA_384:
            case ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                return SimpleDigestPassword.class;
            }
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512: {
                return SaltedSimpleDigestPassword.class;
            }
            case ALGORITHM_CRYPT_DES: {
                return UnixDESCryptPassword.class;
            }
            case ALGORITHM_BSD_CRYPT_DES: {
                return BSDUnixDESCryptPassword.class;
            }
            case ALGORITHM_SCRAM_SHA_1:
            case ALGORITHM_SCRAM_SHA_256: {
                return ScramDigestPassword.class;
            }
        }

        throw log.unknownPasswordTypeOrAlgorithm(algorithm);
    }
}
