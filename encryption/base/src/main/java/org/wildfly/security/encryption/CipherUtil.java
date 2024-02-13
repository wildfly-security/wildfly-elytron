/*
 * Copyright 2021 Red Hat, Inc.
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
import static org.wildfly.security.encryption.Common.CIPHER_TEXT_IDENTIFIER;
import static org.wildfly.security.encryption.Common.CIPHER_TEXT_NAME;
import static org.wildfly.security.encryption.Common.VERSION;
import static org.wildfly.security.encryption.Common.toName;
import static org.wildfly.security.encryption.ElytronMessages.log;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.wildfly.common.codec.DecodeException;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;

/**
 * A utility for using {@link Cipher} instances to encrypt and encode as well as decode and decrypt clear text Strings.
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CipherUtil {

    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static String encrypt(final String clearText, final SecretKey secretKey) throws GeneralSecurityException {
        checkNotNullParam("clearText", clearText);
        checkNotNullParam("secretKey", secretKey);

        byte[] result = encrypt(clearText.getBytes(StandardCharsets.UTF_8), secretKey);
        return ByteIterator.ofBytes(result).base64Encode().drainToString();
    }

    public static byte[] encrypt(final byte[] clearBytes, final SecretKey secretKey) throws GeneralSecurityException {
        checkNotNullParam("clearBytes", clearBytes);
        checkNotNullParam("secretKey", secretKey);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] cipherText = cipher.doFinal(clearBytes);
        byte[] iv = cipher.getIV();

        byte[] result = new byte[iv.length + cipherText.length + 6];
        // HEADER 5 Bytes "ELYC" + Version 1
        // Prefix
        result[0] = 'E';
        result[1] = 'L';
        result[2] = 'Y';
        // Version (Initially only version 1 supported)
        result[3] = VERSION;
        // Type - 'C' for CipherText
        result[4] = CIPHER_TEXT_IDENTIFIER;
        // IV Length
        result[5] = (byte) iv.length;
        // IV
        System.arraycopy(iv, 0, result, 6, iv.length);
        // Cipher Text
        System.arraycopy(cipherText, 0, result, 6 + iv.length, cipherText.length);

        return result;
    }

    public static String decrypt(final String token, final SecretKey secretKey) throws GeneralSecurityException {
        checkNotNullParam("secretKey", secretKey);
        try {
            ByteIterator byteIterator = CodePointIterator.ofString(checkNotNullParam("token", token)).base64Decode();
            byte[] clearText = decrypt(byteIterator, secretKey);
            return new String(clearText, StandardCharsets.UTF_8);
        } catch (DecodeException e) {
            throw log.unableToDecodeBase64Token(e);
        }

    }

    public static byte[] decrypt(final byte[] token, final SecretKey secretKey) throws GeneralSecurityException {
        checkNotNullParam("secretKey", secretKey);

        try {
            ByteIterator byteIterator = ByteIterator.ofBytes(token);
            return decrypt(byteIterator, secretKey);

        } catch (DecodeException e) {
            throw log.unableToDecodeBase64Token(e);
        }

    }

    private static byte[] decrypt(final ByteIterator byteIterator, final SecretKey secretKey) throws GeneralSecurityException {
        byte[] prefixVersion = byteIterator.drain(5);
        if (prefixVersion.length < 4 || prefixVersion[0] != 'E' || prefixVersion[1] != 'L' || prefixVersion[2] != 'Y') {
            throw log.badKeyPrefix();
        } else if (prefixVersion[3] != VERSION) {
            throw log.unsupportedVersion(prefixVersion[3], VERSION);
        } else if (prefixVersion[4] != CIPHER_TEXT_IDENTIFIER) {
            throw log.unexpectedTokenType(toName((char) prefixVersion[4]), CIPHER_TEXT_NAME);
        }

        int ivLength = byteIterator.next();
        byte[] iv = byteIterator.drain(ivLength);
        byte[] cipherText = byteIterator.drain();

        // We successfully dissected the token, now decrypt the value.
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        AlgorithmParameterSpec spec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        return cipher.doFinal(cipherText);
    }

}
