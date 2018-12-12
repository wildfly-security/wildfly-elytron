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

package org.wildfly.security.auth.realm.ldap;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.*;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.*;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
import static org.wildfly.security.password.interfaces.UnixDESCryptPassword.ALGORITHM_CRYPT_DES;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.wildfly.common.Assert;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.util.ModularCrypt;
import org.wildfly.security.util._private.Arrays2;

/**
 * A password utility for LDAP formatted passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordPasswordUtil {

    private UserPasswordPasswordUtil() {
    }

    public static Password parseUserPassword(byte[] userPassword) throws InvalidKeySpecException {
        Assert.checkNotNullParam("userPassword", userPassword);
        if (userPassword.length == 0) throw log.emptyParameter("userPassword");

        if (prefixEqual(0, new byte[] { '{', 'S', 'H', 'A' }, userPassword)) {
            if (prefixEqual(4, new byte[] { '}' }, userPassword)) {
                return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_SHA_1, 5, userPassword);
            }
            if (prefixEqual(4, new byte[] { '2', '5', '6', '}' }, userPassword)) {
                return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_SHA_256, 8, userPassword);
            }
            if (prefixEqual(4, new byte[] { '3', '8', '4', '}' }, userPassword)) {
                return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_SHA_384, 8, userPassword);
            }
            if (prefixEqual(4, new byte[] { '5', '1', '2', '}' }, userPassword)) {
                return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_SHA_512, 8, userPassword);
            }
        }
        if (prefixEqual(0, new byte[] { '{', 'S', 'S', 'H', 'A' }, userPassword)) {
            if (prefixEqual(5, new byte[] { '}' }, userPassword)) {
                return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, 6, userPassword);
            }
            if (prefixEqual(5, new byte[] { '2', '5', '6', '}' }, userPassword)) {
                return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, 9, userPassword);
            }
            if (prefixEqual(5, new byte[] { '3', '8', '4', '}' }, userPassword)) {
                return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, 9, userPassword);
            }
            if (prefixEqual(5, new byte[] { '5', '1', '2', '}' }, userPassword)) {
                return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, 9, userPassword);
            }
        }
        if (prefixEqual(0, new byte[] { '{', 'C', 'R', 'Y', 'P', 'T', '}' }, userPassword)) {
            if(userPassword[7] == '_') {
                return createBsdCryptBasedPassword(userPassword);
            } else {
                return createCryptBasedPassword(userPassword);
            }
        }
        if (prefixEqual(0, new byte[] { '{', 'M', 'D', '5', '}' }, userPassword)) {
            return createSimpleDigestPassword(ALGORITHM_SIMPLE_DIGEST_MD5, 5, userPassword);
        }
        if (prefixEqual(0, new byte[] { '{', 'S', 'M', 'D', '5', '}' }, userPassword)) {
            return createSaltedSimpleDigestPassword(ALGORITHM_PASSWORD_SALT_DIGEST_MD5, 6, userPassword);
        }
        if (prefixEqual(0, new byte[] { '{', 'C', 'L', 'E', 'A', 'R', '}' }, userPassword)) {
            return createClearPassword(7, userPassword);
        }

        if(userPassword[0] == '{' && Arrays2.indexOf(userPassword, '}') > 0) {
            throw log.unknownLdapPasswordScheme();
        }
        return createClearPassword(0, userPassword);
    }

    /* fast conversion of char to upper letter (for ASCII only) */
    private static byte upper(byte character) {
        return (byte) (character >= 'a' && character <= 'z' ? character - 'a' + 'A' : character);
    }

    private static boolean prefixEqual(int skip, byte[] pattern, byte[] array) {
        if (skip + pattern.length > array.length) return false;
        for (int i = 0; i < pattern.length; i++) {
            if (upper(array[i+skip]) != pattern[i]) return false;
        }
        return true;
    }

    private static Password createClearPassword(int skip, byte[] userPassword) {
        if (skip != 0) userPassword = Arrays.copyOfRange(userPassword, skip, userPassword.length);
        return ClearPassword.createRaw(ALGORITHM_CLEAR, new String(userPassword, StandardCharsets.UTF_8).toCharArray());
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

        final int lo = ModularCrypt.MOD_CRYPT.decode(userPassword[7] & 0xff);
        final int hi = ModularCrypt.MOD_CRYPT.decode(userPassword[8] & 0xff);
        if (lo == -1 || hi == -1) {
            throw log.invalidSalt((char) lo, (char) hi);
        }
        short salt = (short) (lo | hi << 6);
        byte[] hash = CodePointIterator.ofUtf8Bytes(userPassword, 9, 11).base64Decode(ModularCrypt.MOD_CRYPT, false).drain();

        return UnixDESCryptPassword.createRaw(ALGORITHM_CRYPT_DES, salt, hash);
    }

    private static Password createBsdCryptBasedPassword(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword.length != 27) {
            throw log.insufficientDataToFormDigestAndSalt();
        }

        int b0 = ModularCrypt.MOD_CRYPT.decode(userPassword[8] & 0xff);
        int b1 = ModularCrypt.MOD_CRYPT.decode(userPassword[9] & 0xff);
        int b2 = ModularCrypt.MOD_CRYPT.decode(userPassword[10] & 0xff);
        int b3 = ModularCrypt.MOD_CRYPT.decode(userPassword[11] & 0xff);
        if (b0 == -1 || b1 == -1 || b2 == -1 || b3 == -1) {
            throw log.invalidRounds((char) b0, (char) b1, (char) b2, (char) b3);
        }
        int iterationCount = b0 | b1 << 6 | b2 << 12 | b3 << 18;

        b0 = ModularCrypt.MOD_CRYPT.decode(userPassword[12] & 0xff);
        b1 = ModularCrypt.MOD_CRYPT.decode(userPassword[13] & 0xff);
        b2 = ModularCrypt.MOD_CRYPT.decode(userPassword[14] & 0xff);
        b3 = ModularCrypt.MOD_CRYPT.decode(userPassword[15] & 0xff);
        if (b0 == -1 || b1 == -1 || b2 == -1 || b3 == -1) {
            throw log.invalidSalt((char) b0, (char) b1, (char) b2, (char) b3);
        }
        int salt = b0 | b1 << 6 | b2 << 12 | b3 << 18;

        byte[] hash = CodePointIterator.ofUtf8Bytes(userPassword, 16, 11).base64Decode(ModularCrypt.MOD_CRYPT, false).drain();
        return BSDUnixDESCryptPassword.createRaw(ALGORITHM_BSD_CRYPT_DES, hash, salt, iterationCount);
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

    public static byte[] composeUserPassword(Password password) throws IOException {
        String algorithm = password.getAlgorithm();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (ALGORITHM_SIMPLE_DIGEST_MD5.equals(algorithm)) {
            out.write(new byte[] { '{', 'm', 'd', '5', '}' });
            out.write(ByteIterator.ofBytes(((SimpleDigestPassword)password).getDigest()).base64Encode().asUtf8().drain());
        } else if (ALGORITHM_SIMPLE_DIGEST_SHA_1.equals(algorithm)) {
            out.write(new byte[]{'{','s','h','a','}'});
            out.write(ByteIterator.ofBytes(((SimpleDigestPassword)password).getDigest()).base64Encode().asUtf8().drain());
        } else if (ALGORITHM_SIMPLE_DIGEST_SHA_256.equals(algorithm)) {
            out.write(new byte[]{'{','s','h','a','2','5','6','}'});
            out.write(ByteIterator.ofBytes(((SimpleDigestPassword)password).getDigest()).base64Encode().asUtf8().drain());
        } else if (ALGORITHM_SIMPLE_DIGEST_SHA_384.equals(algorithm)) {
            out.write(new byte[]{'{','s','h','a','3','8','4','}'});
            out.write(ByteIterator.ofBytes(((SimpleDigestPassword)password).getDigest()).base64Encode().asUtf8().drain());
        } else if (ALGORITHM_SIMPLE_DIGEST_SHA_512.equals(algorithm)) {
            out.write(new byte[]{'{','s','h','a','5','1','2','}'});
            out.write(ByteIterator.ofBytes(((SimpleDigestPassword)password).getDigest()).base64Encode().asUtf8().drain());
        } else if (ALGORITHM_PASSWORD_SALT_DIGEST_MD5.equals(algorithm)) {
            out.write(new byte[]{'{','s','m','d','5','}'});
            out.write(composeDigestSalt((SaltedSimpleDigestPassword) password));
        } else if (ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1.equals(algorithm)) {
            out.write(new byte[]{'{','s','s','h','a','}'});
            out.write(composeDigestSalt((SaltedSimpleDigestPassword) password));
        } else if (ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256.equals(algorithm)) {
            out.write(new byte[]{'{','s','s','h','a','2','5','6','}'});
            out.write(composeDigestSalt((SaltedSimpleDigestPassword) password));
        } else if (ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384.equals(algorithm)) {
            out.write(new byte[]{'{','s','s','h','a','3','8','4','}'});
            out.write(composeDigestSalt((SaltedSimpleDigestPassword) password));
        } else if (ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512.equals(algorithm)) {
            out.write(new byte[]{'{','s','s','h','a','5','1','2','}'});
            out.write(composeDigestSalt((SaltedSimpleDigestPassword) password));
        } else if (ALGORITHM_BSD_CRYPT_DES.equals(algorithm)) {
            out.write(new byte[] { '{', 'c', 'r', 'y', 'p', 't', '}', '_' });
            composeBsdCryptBasedPassword(out, (BSDUnixDESCryptPassword) password);
        } else if (ALGORITHM_CRYPT_DES.equals(algorithm)) {
            out.write(new byte[]{'{','c','r','y','p','t','}'});
            composeCryptBasedPassword(out, (UnixDESCryptPassword) password);
        } else if (ALGORITHM_CLEAR.equals(algorithm)) {
            return CodePointIterator.ofChars(((ClearPassword)password).getPassword()).asUtf8().drain();
        } else {
            return null;
        }
        return out.toByteArray();
    }

    private static byte[] composeDigestSalt(SaltedSimpleDigestPassword password) {
        return ByteIterator.ofBytes(new ByteStringBuilder()
                        .append(password.getDigest())
                        .append(password.getSalt())
                        .toArray()
                    ).base64Encode().asUtf8().drain();
    }

    private static void composeCryptBasedPassword(ByteArrayOutputStream out, UnixDESCryptPassword password) throws IOException {
        out.write(ModularCrypt.MOD_CRYPT.encode(password.getSalt() & 0x3f));
        out.write(ModularCrypt.MOD_CRYPT.encode(password.getSalt() >> 6 & 0x3f));
        out.write(ByteIterator.ofBytes(password.getHash()).base64Encode(ModularCrypt.MOD_CRYPT, false).asUtf8().drain());
    }

    private static void composeBsdCryptBasedPassword(ByteArrayOutputStream out, BSDUnixDESCryptPassword password) throws IOException {

        out.write(ModularCrypt.MOD_CRYPT.encode(password.getIterationCount() & 0x3f));
        out.write(ModularCrypt.MOD_CRYPT.encode(password.getIterationCount() >> 6 & 0x3f));
        out.write(ModularCrypt.MOD_CRYPT.encode(password.getIterationCount() >> 12 & 0x3f));
        out.write(ModularCrypt.MOD_CRYPT.encode(password.getIterationCount() >> 18 & 0x3f));

        out.write(ModularCrypt.MOD_CRYPT.encode(password.getSalt() & 0x3f));
        out.write(ModularCrypt.MOD_CRYPT.encode(password.getSalt() >> 6 & 0x3f));
        out.write(ModularCrypt.MOD_CRYPT.encode(password.getSalt() >> 12 & 0x3f));
        out.write(ModularCrypt.MOD_CRYPT.encode(password.getSalt() >> 18 & 0x3f));

        out.write(ByteIterator.ofBytes(password.getHash()).base64Encode(ModularCrypt.MOD_CRYPT, false).asUtf8().drain());
    }

    public static boolean isAlgorithmSupported(String algorithm) {
        switch (algorithm) {
            case ALGORITHM_SIMPLE_DIGEST_MD5:
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:
            case ALGORITHM_SIMPLE_DIGEST_SHA_256:
            case ALGORITHM_SIMPLE_DIGEST_SHA_384:
            case ALGORITHM_SIMPLE_DIGEST_SHA_512:
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_BSD_CRYPT_DES:
            case ALGORITHM_CRYPT_DES:
            case ALGORITHM_CLEAR:
                return true;
            default:
                return false;
        }
    }
}
