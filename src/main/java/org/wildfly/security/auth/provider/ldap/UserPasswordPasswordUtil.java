/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.auth.provider.ldap;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.*;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.*;

import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;

import org.wildfly.common.Assert;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.util.Alphabet.Base64Alphabet;
import org.wildfly.security.util.CodePointIterator;

/**
 * A password utility for LDAP formatted passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordPasswordUtil {

    private UserPasswordPasswordUtil() {
    }

    public static Password parseUserPassword(byte[] userPassword, String requiredType) throws InvalidKeySpecException {
        Assert.checkNotNullParam("userPassword", userPassword);
        if (userPassword.length == 0) throw log.emptyParameter("userPassword");

        if (userPassword[0] != '{') {
            return createClearPassword(userPassword);
        } else {
            if (userPassword[1] == 'm' && userPassword[2] == 'd' && userPassword[3] == '5' && userPassword[4] == '}') {
                // {md5}
                if ( ! "md5".equals(requiredType)) return null;
                return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_MD5, 5, userPassword);
            } else if (userPassword[1] == 's' && userPassword[2] == 'h' && userPassword[3] == 'a') {
                if (userPassword[4] == '}') {
                    // {sha}
                    if ( ! "sha1".equals(requiredType)) return null;
                    return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_SHA_1, 5, userPassword);
                } else if (userPassword[4] == '2' && userPassword[5] == '5' && userPassword[6] == '6' && userPassword[7] == '}') {
                    // {sha256}
                    if ( ! "sha256".equals(requiredType)) return null;
                    return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_SHA_256, 8, userPassword);
                } else if (userPassword[4] == '3' && userPassword[5] == '8' && userPassword[6] == '4' && userPassword[7] == '}') {
                    // {sha384}
                    if ( ! "sha384".equals(requiredType)) return null;
                    return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_SHA_384, 8, userPassword);
                } else if (userPassword[4] == '5' && userPassword[5] == '1' && userPassword[6] == '2' && userPassword[7] == '}') {
                    // {sha512}
                    if ( ! "sha512".equals(requiredType)) return null;
                    return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_SHA_512, 8, userPassword);
                }
            } else if (userPassword[1] == 's' && userPassword[2] == 'm' && userPassword[3] == 'd' && userPassword[4] == '5' && userPassword[5] == '}') {
                // {smd5}
                if ( ! "smd5".equals(requiredType)) return null;
                return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_MD5, 6, userPassword);
            } else if (userPassword[1] == 's' && userPassword[2] == 's' && userPassword[3] == 'h' && userPassword[4] == 'a') {
                if (userPassword[5] == '}') {
                    // {ssha}
                    if ( ! "ssha".equals(requiredType)) return null;
                    return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, 6, userPassword);
                } else if (userPassword[5] == '2' && userPassword[6] == '5' && userPassword[7] == '6' && userPassword[8] == '}') {
                    // {ssha256}
                    if ( ! "ssha256".equals(requiredType)) return null;
                    return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, 9, userPassword);
                } else if (userPassword[5] == '3' && userPassword[6] == '8' && userPassword[7] == '4' && userPassword[8] == '}') {
                    // {ssha384}
                    if ( ! "ssha384".equals(requiredType)) return null;
                    return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, 9, userPassword);
                } else if (userPassword[5] == '5' && userPassword[6] == '1' && userPassword[7] == '2' && userPassword[8] == '}') {
                    // {ssha512}
                    if ( ! "ssha512".equals(requiredType)) return null;
                    return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, 9, userPassword);
                }
            } else if (userPassword[1] == 'c' && userPassword[2] == 'r' && userPassword[3] == 'y' && userPassword[4] == 'p' && userPassword[5] == 't' && userPassword[6] == '}') {
                if (userPassword[7] == '_') {
                    // {crypt}_
                    if ( ! "crypt_".equals(requiredType)) return null;
                    return createBsdCryptBasedPassword(userPassword);
                } else {
                    // {crypt}
                    if ( ! "crypt".equals(requiredType)) return null;
                    return createCryptBasedPassword(userPassword);
                }
            }
            if ( ! "clear".equals(requiredType)) return null;
            for (int i = 1; i < userPassword.length - 1; i++) {
                if (userPassword[i] == '}') {
                    throw new InvalidKeySpecException();
                }
            }
            return createClearPassword(userPassword);
        }
    }

    private static Password createClearPassword(byte[] userPassword) {
        return ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, new String(userPassword, StandardCharsets.UTF_8).toCharArray());
    }

    private static Password createSimpleDigestPassword(String algorithm, int prefixSize, byte[] userPassword)
            throws InvalidKeySpecException {
        int length = userPassword.length - prefixSize;
        byte[] digest = CodePointIterator.ofUtf8Bytes(userPassword, prefixSize, length).base64Decode().drain();
        return SimpleDigestPassword.createRaw(algorithm, digest);
    }

    private static Password createSaltedSimpleDigestPassword(String algorithm, int prefixSize, byte[] userPassword)
            throws InvalidKeySpecException {
        int length = userPassword.length - prefixSize;
        byte[] decoded = CodePointIterator.ofUtf8Bytes(userPassword, prefixSize, length).base64Decode().drain();

        int digestLength = expectedDigestLengthBytes(algorithm);
        int saltLength = decoded.length - digestLength;
        if (saltLength < 1) {
            throw log.insufficientDataToFormDigestAndSalt();
        }

        byte[] digest = new byte[digestLength];
        byte[] salt = new byte[saltLength];
        System.arraycopy(decoded, 0, digest, 0, digestLength);
        System.arraycopy(decoded, digestLength, salt, 0, saltLength);

        return SaltedSimpleDigestPassword.createRaw(algorithm, digest, salt);
    }

    private static Password createCryptBasedPassword(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword.length != 20) {
            throw log.insufficientDataToFormDigestAndSalt();
        }

        final int lo = Base64Alphabet.MOD_CRYPT.decode(userPassword[7] & 0xff);
        final int hi = Base64Alphabet.MOD_CRYPT.decode(userPassword[8] & 0xff);
        if (lo == -1 || hi == -1) {
            throw log.invalidSalt((char) lo, (char) hi);
        }
        short salt = (short) (lo | hi << 6);
        byte[] hash = CodePointIterator.ofUtf8Bytes(userPassword, 9, 11).base64Decode(Base64Alphabet.MOD_CRYPT, false).drain();

        return UnixDESCryptPassword.createRaw(UnixDESCryptPassword.ALGORITHM_CRYPT_DES, salt, hash);
    }

    private static Password createBsdCryptBasedPassword(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword.length != 27) {
            throw log.insufficientDataToFormDigestAndSalt();
        }

        int b0 = Base64Alphabet.MOD_CRYPT.decode(userPassword[8] & 0xff);
        int b1 = Base64Alphabet.MOD_CRYPT.decode(userPassword[9] & 0xff);
        int b2 = Base64Alphabet.MOD_CRYPT.decode(userPassword[10] & 0xff);
        int b3 = Base64Alphabet.MOD_CRYPT.decode(userPassword[11] & 0xff);
        if (b0 == -1 || b1 == -1 || b2 == -1 || b3 == -1) {
            throw log.invalidRounds((char) b0, (char) b1, (char) b2, (char) b3);
        }
        int iterationCount = b0 | b1 << 6 | b2 << 12 | b3 << 18;

        b0 = Base64Alphabet.MOD_CRYPT.decode(userPassword[12] & 0xff);
        b1 = Base64Alphabet.MOD_CRYPT.decode(userPassword[13] & 0xff);
        b2 = Base64Alphabet.MOD_CRYPT.decode(userPassword[14] & 0xff);
        b3 = Base64Alphabet.MOD_CRYPT.decode(userPassword[15] & 0xff);
        if (b0 == -1 || b1 == -1 || b2 == -1 || b3 == -1) {
            throw log.invalidSalt((char) b0, (char) b1, (char) b2, (char) b3);
        }
        int salt = b0 | b1 << 6 | b2 << 12 | b3 << 18;

        byte[] hash = CodePointIterator.ofUtf8Bytes(userPassword, 16, 11).base64Decode(Base64Alphabet.MOD_CRYPT, false).drain();
        return BSDUnixDESCryptPassword.createRaw(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, hash, salt, iterationCount);
    }

    private static int expectedDigestLengthBytes(final String algorithm) {
        switch (algorithm) {
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
                return 16;
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
                return 20;
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
                return 32;
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
                return 48;
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
                return 64;
            default:
                throw log.unrecognizedAlgorithm(algorithm);
        }
    }
}
