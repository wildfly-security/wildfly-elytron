/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.encryption;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.encryption.Common.SECRET_KEY_IDENTIFIER;
import static org.wildfly.security.encryption.Common.SECRET_KEY_NAME;
import static org.wildfly.security.encryption.Common.VERSION;
import static org.wildfly.security.encryption.Common.toName;
import static org.wildfly.security.encryption.ElytronMessages.log;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.wildfly.common.codec.DecodeException;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;


/**
 * Utility methods for operating on {@code SecretKey} instances.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SecretKeyUtil {

    private static final String SECRET_KEY_ALGORITHM = "AES";

    public static SecretKey generateSecretKey(int keySize) throws GeneralSecurityException {
        checkKeySize(keySize);

        SecureRandom random = new SecureRandom();
        final byte[] rawKey = new byte[keySize / 8];
        random.nextBytes(rawKey);

        SecretKey secretKey = new SecretKeySpec(rawKey, SECRET_KEY_ALGORITHM);
        Arrays.fill(rawKey, (byte) 0);

        return secretKey;
    }

    public static String exportSecretKey(final SecretKey secretKey) throws GeneralSecurityException {
        checkNotNullParam("secretKey", secretKey);

        byte[] key = secretKey.getEncoded();
        checkKeySize(key.length * 8);

        byte[] result = new byte[key.length + 5];
        // Prefix
        result[0] = 'E';
        result[1] = 'L';
        result[2] = 'Y';
        // Version (Initially only version 1 supported)
        result[3] = VERSION;
        // Type - 'K' for Key
        result[4] = SECRET_KEY_IDENTIFIER;

        System.arraycopy(key, 0, result, 5, key.length);

        return ByteIterator.ofBytes(result).base64Encode().drainToString();
    }

    public static SecretKey importSecretKey(final char[] rawData, int offset, int length) throws GeneralSecurityException {
        return importSecretKey(CodePointIterator.ofChars(checkNotNullParam("rawData", rawData), offset, length));
    }

    public static SecretKey importSecretKey(final String secretKey) throws GeneralSecurityException {
        return importSecretKey(CodePointIterator.ofString(checkNotNullParam("secretKey", secretKey)));
    }

    private static SecretKey importSecretKey(CodePointIterator codePointIterator) throws GeneralSecurityException {
        try {
            ByteIterator byteIterator = codePointIterator.base64Decode();

            byte[] prefixVersion = byteIterator.drain(5);
            if (prefixVersion.length < 4 || prefixVersion[0] != 'E' || prefixVersion[1] != 'L' || prefixVersion[2] != 'Y') {
                throw log.badKeyPrefix();
            } else if (prefixVersion[3] != VERSION) {
                throw log.unsupportedVersion(prefixVersion[3], VERSION);
            } else if (prefixVersion[4] != SECRET_KEY_IDENTIFIER) {
                throw log.unexpectedTokenType(toName((char) prefixVersion[4]), SECRET_KEY_NAME);
            }

            byte[] key = byteIterator.drain();
            checkKeySize(key.length * 8);

            return new SecretKeySpec(key, SECRET_KEY_ALGORITHM);

        } catch (DecodeException e) {
            throw log.unableToDecodeBase64Token(e);
        }
    }

    private static void checkKeySize(final int keySize) throws GeneralSecurityException {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw log.badKeySize();
        }
    }

}
