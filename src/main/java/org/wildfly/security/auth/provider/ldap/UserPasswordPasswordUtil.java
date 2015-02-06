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

import static org.wildfly.security.password.interfaces.SimpleDigestPassword.*;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.*;

import java.nio.charset.Charset;
import java.security.spec.InvalidKeySpecException;

import org.wildfly.security.password.spec.BSDUnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.SimpleDigestPasswordSpec;
import org.wildfly.security.password.spec.SaltedSimpleDigestPasswordSpec;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.CodePointIterator;

/**
 * A password utility for LDAP formatted passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordPasswordUtil {

    static final Charset UTF_8 = Charset.forName("UTF-8");

    private UserPasswordPasswordUtil() {
    }

    public static PasswordSpec parseUserPassword(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword == null || userPassword.length == 0) {
            throw new IllegalArgumentException("userPassword can not be null or empty.");
        }

        if (userPassword[0] != '{') {
            return createClearPasswordSpec(userPassword);
        } else {
            if (userPassword[1] == 'm' && userPassword[2] == 'd' && userPassword[3] == '5' && userPassword[4] == '}') {
                // {md5}
                return createSimpleDigestPasswordSpec(ALGORITHM_DIGEST_MD5, 5, userPassword);
            } else if (userPassword[1] == 's' && userPassword[2] == 'h' && userPassword[3] == 'a') {
                if (userPassword[4] == '}') {
                    // {sha}
                    return createSimpleDigestPasswordSpec(ALGORITHM_DIGEST_SHA_1, 5, userPassword);
                } else if (userPassword[4] == '2' && userPassword[5] == '5' && userPassword[6] == '6' && userPassword[7] == '}') {
                    // {sha256}
                    return createSimpleDigestPasswordSpec(ALGORITHM_DIGEST_SHA_256, 8, userPassword);
                } else if (userPassword[4] == '3' && userPassword[5] == '8' && userPassword[6] == '4' && userPassword[7] == '}') {
                    // {sha384}
                    return createSimpleDigestPasswordSpec(ALGORITHM_DIGEST_SHA_384, 8, userPassword);
                } else if (userPassword[4] == '5' && userPassword[5] == '1' && userPassword[6] == '2' && userPassword[7] == '}') {
                    // {sha512}
                    return createSimpleDigestPasswordSpec(ALGORITHM_DIGEST_SHA_512, 8, userPassword);
                }
            } else if (userPassword[1] == 's' && userPassword[2] == 'm' && userPassword[3] == 'd' && userPassword[4] == '5' && userPassword[5] == '}') {
                // {smd5}
                return createSaltedSimpleDigestPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_MD5, 6, userPassword);
            } else if (userPassword[1] == 's' && userPassword[2] == 's' && userPassword[3] == 'h' && userPassword[4] == 'a') {
                if (userPassword[5] == '}') {
                    // {ssha}
                    return createSaltedSimpleDigestPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, 6, userPassword);
                } else if (userPassword[5] == '2' && userPassword[6] == '5' && userPassword[7] == '6' && userPassword[8] == '}') {
                    // {ssha256}
                    return createSaltedSimpleDigestPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, 9, userPassword);
                } else if (userPassword[5] == '3' && userPassword[6] == '8' && userPassword[7] == '4' && userPassword[8] == '}') {
                    // {ssha384}
                    return createSaltedSimpleDigestPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, 9, userPassword);
                } else if (userPassword[5] == '5' && userPassword[6] == '1' && userPassword[7] == '2' && userPassword[8] == '}') {
                    // {ssha512}
                    return createSaltedSimpleDigestPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, 9, userPassword);
                }
            } else if (userPassword[1] == 'c' && userPassword[2] == 'r' && userPassword[3] == 'y' && userPassword[4] == 'p' && userPassword[5] == 't' && userPassword[6] == '}') {
                return createCryptBasedSpec(userPassword);
            }
            for (int i = 1; i < userPassword.length - 1; i++) {
                if (userPassword[i] == '}') {
                    throw new InvalidKeySpecException();
                }
            }
            return createClearPasswordSpec(userPassword);
        }
    }

    private static PasswordSpec createClearPasswordSpec(byte[] userPassword) {
        return new ClearPasswordSpec(new String(userPassword, UTF_8).toCharArray());
    }

    private static PasswordSpec createSimpleDigestPasswordSpec(String algorithm, int prefixSize, byte[] userPassword)
            throws InvalidKeySpecException {
        int length = userPassword.length - prefixSize;
        byte[] digest = CodePointIterator.ofUtf8Bytes(userPassword, prefixSize, length).base64Decode().drain();

        return new SimpleDigestPasswordSpec(algorithm, digest);
    }

    private static PasswordSpec createSaltedSimpleDigestPasswordSpec(String algorithm, int prefixSize, byte[] userPassword)
            throws InvalidKeySpecException {
        int length = userPassword.length - prefixSize;
        byte[] decoded = CodePointIterator.ofUtf8Bytes(userPassword, prefixSize, length).base64Decode().drain();

        int digestLength = expectedDigestLengthBytes(algorithm);
        int saltLength = decoded.length - digestLength;
        if (saltLength < 1) {
            throw new InvalidKeySpecException("Insufficient data to form a digest and a salt.");
        }

        byte[] digest = new byte[digestLength];
        byte[] salt = new byte[saltLength];
        System.arraycopy(decoded, 0, digest, 0, digestLength);
        System.arraycopy(decoded, digestLength, salt, 0, saltLength);

        return new SaltedSimpleDigestPasswordSpec(algorithm, digest, salt);
    }

    private static PasswordSpec createCryptBasedSpec(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword.length != 20) {
            throw new InvalidKeySpecException("Insufficient data to form a digest and a salt.");
        }

        final int iterationCount = 25; // Apache DS fix this at 25 so not represented in the userPassword value.

        final int lo = Alphabet.MOD_CRYPT.decode(userPassword[7] & 0xff);
        final int hi = Alphabet.MOD_CRYPT.decode(userPassword[8] & 0xff);
        if (lo == -1 || hi == -1) {
            throw new IllegalArgumentException(String.format("Invalid salt (%s%s)", (char) lo, (char) hi));
        }
        int salt = lo | hi << 6;
        byte[] hash = CodePointIterator.ofUtf8Bytes(userPassword, 9, 11).base64Decode(Alphabet.MOD_CRYPT, false).drain();

        return new BSDUnixDESCryptPasswordSpec(hash, salt, iterationCount);
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
                throw new IllegalArgumentException("Unrecognised algorithm.");
        }
    }
}
