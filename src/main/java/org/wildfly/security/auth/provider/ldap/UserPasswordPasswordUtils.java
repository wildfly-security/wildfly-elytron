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

import static org.wildfly.security.password.interfaces.TrivialDigestPassword.*;
import static org.wildfly.security.password.interfaces.TrivialSaltedDigestPassword.*;

import java.io.Closeable;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;

import org.wildfly.security.password.spec.BSDUnixDESCryptPasswordSpec;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.TrivialDigestPasswordSpec;
import org.wildfly.security.password.spec.TrivialSaltedDigestPasswordSpec;
import org.wildfly.security.util.Base64;
import org.wildfly.security.util.CharacterArrayReader;

/**
 * A password utility for LDAP formatted passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordPasswordUtils {

    static final Charset UTF_8 = Charset.forName("UTF-8");

    private UserPasswordPasswordUtils() {
    }

    public static PasswordSpec parseUserPassword(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword == null || userPassword.length == 0) {
            throw new IllegalArgumentException("userPassword can not be null or empty.");
        }

        if (userPassword[0] != '{') {
            return createClearPasswordSpec(userPassword);
        } else {
            if (userPassword[1] == 's' && userPassword[2] == 'h' && userPassword[3] == 'a') {
                if (userPassword[4] == '}') {
                    // {sha}
                    return createTrivialDigestSpec(ALGORITHM_DIGEST_SHA_1, 5, userPassword);
                } else if (userPassword[4] == '2' && userPassword[5] == '5' && userPassword[6] == '6' && userPassword[7] == '}') {
                    // {sha256}
                    return createTrivialDigestSpec(ALGORITHM_DIGEST_SHA_256, 8, userPassword);
                } else if (userPassword[4] == '3' && userPassword[5] == '8' && userPassword[6] == '4' && userPassword[7] == '}') {
                    // {sha384}
                    return createTrivialDigestSpec(ALGORITHM_DIGEST_SHA_384, 8, userPassword);
                } else if (userPassword[4] == '5' && userPassword[5] == '1' && userPassword[6] == '2' && userPassword[7] == '}') {
                    // {sha512}
                    return createTrivialDigestSpec(ALGORITHM_DIGEST_SHA_512, 8, userPassword);
                }
            } else if (userPassword[1] == 's' && userPassword[2] == 's' && userPassword[3] == 'h' && userPassword[4] == 'a') {
                if (userPassword[5] == '}') {
                    // {ssha}
                    return createTrivialSaltedPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, 6, userPassword);
                } else if (userPassword[5] == '2' && userPassword[6] == '5' && userPassword[7] == '6' && userPassword[8] == '}') {
                    // {ssha256}
                    return createTrivialSaltedPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, 9, userPassword);
                } else if (userPassword[5] == '3' && userPassword[6] == '8' && userPassword[7] == '4' && userPassword[8] == '}') {
                    // {ssha384}
                    return createTrivialSaltedPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, 9, userPassword);
                } else if (userPassword[5] == '5' && userPassword[6] == '1' && userPassword[7] == '2' && userPassword[8] == '}') {
                    // {ssha512}
                    return createTrivialSaltedPasswordSpec(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, 9, userPassword);
                }
            } else if (userPassword[1] == 'c' && userPassword[2] == 'r' && userPassword[3] == 'y' && userPassword[4] == 'p' && userPassword[5] == 't' && userPassword[6] == '}') {
                return createCrypBasedSpec(userPassword);
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

    private static PasswordSpec createTrivialDigestSpec(String algorithm, int prefixSize, byte[] userPassword)
            throws InvalidKeySpecException {
        int length = userPassword.length - prefixSize;
        char[] encodedBase64 = new String(userPassword, prefixSize, length, UTF_8).toCharArray();
        byte[] digest = Base64.base64DecodeStandard(encodedBase64, 0);

        return new TrivialDigestPasswordSpec(algorithm, digest);
    }

    private static PasswordSpec createTrivialSaltedPasswordSpec(String algorithm, int prefixSize, byte[] userPassword)
            throws InvalidKeySpecException {
        int length = userPassword.length - prefixSize;
        char[] encodedBase64 = new String(userPassword, prefixSize, length, UTF_8).toCharArray();
        byte[] decoded = Base64.base64DecodeStandard(encodedBase64, 0);

        int digestLength = expectedDigestLengthBytes(algorithm);
        int saltLength = decoded.length - digestLength;
        if (saltLength < 1) {
            throw new InvalidKeySpecException("Insufficient data to form a digest and a salt.");
        }

        byte[] digest = new byte[digestLength];
        byte[] salt = new byte[saltLength];
        System.arraycopy(decoded, 0, digest, 0, digestLength);
        System.arraycopy(decoded, digestLength, salt, 0, saltLength);

        return new TrivialSaltedDigestPasswordSpec(algorithm, digest, salt);
    }

    private static PasswordSpec createCrypBasedSpec(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword.length != 20) {
            throw new InvalidKeySpecException("Insufficient data to form a digest and a salt.");
        }

        final int iterationCount = 25; // Apache DS fix this at 25 so not represented in the userPassword value.

        byte[] saltBytes = new byte[2];
        System.arraycopy(userPassword, 7, saltBytes, 0, 2);
        int salt = 0;
        for (int i = 1; i >= 0; i--) {
            salt = ( salt << 6 ) | ( 0x00ff & Base64.base64DecodeModCrypt(saltBytes[i]));
        }

        byte[] hash = new byte[8];
        CharacterArrayReader r = new CharacterArrayReader(new String(userPassword, 9, 11, StandardCharsets.UTF_8).toCharArray());
        try {
            Base64.base64DecodeModCrypt(r, hash);
        } finally {
            safeClose(r);
        }

        return new BSDUnixDESCryptPasswordSpec(hash, salt, iterationCount);
    }

    private static int expectedDigestLengthBytes(final String algorithm) {
        switch (algorithm) {
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

    private static void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }
}
