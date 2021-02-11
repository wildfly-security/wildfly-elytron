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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.wildfly.security.encryption.CipherUtil.decrypt;
import static org.wildfly.security.encryption.CipherUtil.encrypt;
import static org.wildfly.security.encryption.Common.SECRET_KEY_IDENTIFIER;
import static org.wildfly.security.encryption.Common.VERSION;
import static org.wildfly.security.encryption.SecretKeyUtil.generateSecretKey;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;

/**
 * Test case to test the {@code CipherUtil} implementation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CipherUtilTest {

    private static final String CLEAR_TEXT = "Lorem ipsum dolor sit amet";

    @Test
    public void testEncryptDecryptRoundTrip() throws GeneralSecurityException {
        SecretKey secretKey = generateSecretKey(256);

        // Encrypt the same text twice as each should use a unique IV resulting
        // in a unique response.
        String cipherOne = encrypt(CLEAR_TEXT, secretKey);
        String cipherTwo = encrypt(CLEAR_TEXT, secretKey);
        assertNotEquals("Cipher text should differ", cipherOne,  cipherTwo);

        String clearOne = decrypt(cipherOne, secretKey);
        String clearTwo = decrypt(cipherTwo, secretKey);

        assertEquals("Successful decryption", CLEAR_TEXT, clearOne);
        assertEquals("Successful decryption", CLEAR_TEXT, clearTwo);
    }

    @Test(expected=GeneralSecurityException.class)
    public void testBadPrefix() throws Exception {
        SecretKey secretKey = generateSecretKey(256);
        String cipherText = encrypt(CLEAR_TEXT, secretKey);

        byte[] raw = CodePointIterator.ofString(cipherText).base64Decode().drain();
        raw[0] = 0x00;
        raw[1] = 0x00;
        raw[2] = 0x00;
        String encoded = ByteIterator.ofBytes(raw).base64Encode().drainToString();

        decrypt(encoded, secretKey);
    }

    @Test(expected = GeneralSecurityException.class)
    public void testBadVersion() throws Exception {
        SecretKey secretKey = generateSecretKey(256);
        String cipherText = encrypt(CLEAR_TEXT, secretKey);

        byte[] raw = CodePointIterator.ofString(cipherText).base64Decode().drain();
        raw[3] = VERSION + 1;  // We don't want to test all bad versions but do want to be sure the next version is automatically rejected.
        String encoded = ByteIterator.ofBytes(raw).base64Encode().drainToString();

        decrypt(encoded, secretKey);
    }

    @Test(expected = GeneralSecurityException.class)
    public void testBadTokenType() throws Exception {
        SecretKey secretKey = generateSecretKey(256);
        String cipherText = encrypt(CLEAR_TEXT, secretKey);

        byte[] raw = CodePointIterator.ofString(cipherText).base64Decode().drain();
        raw[4] = SECRET_KEY_IDENTIFIER;
        String encoded = ByteIterator.ofBytes(raw).base64Encode().drainToString();

        decrypt(encoded, secretKey);
    }

}
