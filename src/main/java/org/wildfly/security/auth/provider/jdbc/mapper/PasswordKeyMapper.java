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

import org.wildfly.security.auth.provider.jdbc.KeyMapper;
import org.wildfly.security.auth.spi.CredentialSupport;
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
import org.wildfly.security.password.spec.BCryptPasswordSpec;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.SaltedSimpleDigestPasswordSpec;
import org.wildfly.security.password.spec.ScramDigestPasswordSpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.ResultSet;

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
 * A {@link KeyMapper} that knows how to map columns to a {@link org.wildfly.security.password.Password} instance.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PasswordKeyMapper implements KeyMapper {

    private final int hash;
    private final String algorithm;
    private final int salt;
    private final int iterationCount;
    private final Class<?> passwordType;

    public PasswordKeyMapper(String algorithm, int hash, int salt, int iterationCount) throws InvalidKeyException {
        this.algorithm = algorithm;
        this.passwordType = toPasswordType(algorithm);
        this.hash = hash;
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    public PasswordKeyMapper(String algorithm, int hash) throws InvalidKeyException {
        this(algorithm, hash, -1, -1);
    }

    public PasswordKeyMapper(String algorithm, int hash, int salt) throws InvalidKeyException {
        this(algorithm, hash, salt, -1);
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
        Object hash = null;
        Object salt = null;
        int iterationCount = 0;

        try {
            while (resultSet.next()) {
                hash = resultSet.getObject(getHash());

                int saltIndex = getSalt();

                if (saltIndex > 0) {
                    salt = resultSet.getObject(saltIndex);
                }

                int iterationCountIndex = getIterationCount();

                if (iterationCountIndex > 0) {
                    iterationCount = resultSet.getInt(iterationCountIndex);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Could not obtain credential.", e);
        }

        if (hash != null) {
            PasswordFactory passwordFactory = getPasswordFactory(getAlgorithm());

            try {
                Class<?> credentialType = getKeyType();

                if (ClearPassword.class.equals(credentialType)) {
                    return passwordFactory.generatePassword(new ClearPasswordSpec(hash.toString().toCharArray()));
                } else if (BCryptPassword.class.equals(credentialType)) {
                    BCryptPasswordSpec bCryptPasswordSpec = (BCryptPasswordSpec) PasswordUtil.parseCryptString(hash.toString().toCharArray());
                    return passwordFactory.generatePassword(bCryptPasswordSpec);
                } else if (SaltedSimpleDigestPassword.class.equals(credentialType)) {
                    return toSaltedSimpleDigestPassword(hash, salt, passwordFactory);
                } else if (ScramDigestPassword.class.equals(credentialType)) {
                    return toScramDigestPassword(hash, salt, iterationCount, passwordFactory);
                }
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException("Invalid password key specification for algorithm [" + algorithm + "].", e);
            }
        }

        return null;
    }

    private Object toScramDigestPassword(Object hash, Object salt, int iterationCount, PasswordFactory passwordFactory) throws InvalidKeySpecException {
        if (salt == null) {
            throw new RuntimeException("Salt is expected when creating [" + ScramDigestPassword.class + "] passwords.");
        }

        byte[] hashBytes = null;

        if (String.class.isInstance(hash)) {
            hashBytes = hash.toString().getBytes();
        } else if (byte[].class.isInstance(hash)) {
            hashBytes = (byte[]) hash;
        }

        byte[] saltBytes = null;

        if (String.class.isInstance(salt)) {
            saltBytes = salt.toString().getBytes();
        } else if (byte[].class.isInstance(salt)) {
            saltBytes = (byte[]) salt;
        }

        ScramDigestPasswordSpec saltedSimpleDigestPasswordSpec = new ScramDigestPasswordSpec(algorithm, hashBytes, saltBytes, iterationCount);

        return passwordFactory.generatePassword(saltedSimpleDigestPasswordSpec);
    }

    private Object toSaltedSimpleDigestPassword(Object hash, Object salt, PasswordFactory passwordFactory) throws InvalidKeySpecException {
        if (salt == null) {
            throw new RuntimeException("Salt is expected when creating [" + SaltedSimpleDigestPassword.class + "] passwords.");
        }

        byte[] hashBytes = null;

        if (String.class.isInstance(hash)) {
            hashBytes = hash.toString().getBytes();
        } else if (byte[].class.isInstance(hash)) {
            hashBytes = (byte[]) hash;
        }

        byte[] saltBytes = null;

        if (String.class.isInstance(salt)) {
            saltBytes = salt.toString().getBytes();
        } else if (byte[].class.isInstance(salt)) {
            saltBytes = (byte[]) salt;
        }

        SaltedSimpleDigestPasswordSpec saltedSimpleDigestPasswordSpec = new SaltedSimpleDigestPasswordSpec(algorithm, hashBytes, saltBytes);

        return passwordFactory.generatePassword(saltedSimpleDigestPasswordSpec);
    }

    private PasswordFactory getPasswordFactory(String algorithm) {
        try {
            return PasswordFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not obtain PasswordFactory for algorithm [" + algorithm + "].", e);
        }
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

        throw new InvalidKeyException("Unknown password type or algorithm");
    }
}
