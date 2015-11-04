/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.credential.store.external;

import static org.wildfly.security._private.ElytronMessages.log;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.ByteIterator;

/**
 * Class that supports decoding of masked password from PicketBox code base.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class MaskedPasswordDecoder {

    /**
     * Prefix to used when masked password needs to be detected.
     */
    public static String PASS_MASK_PREFIX = "MASK-";

    private static final char[] DEFAULT_PBE_KEY = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
    static final String DEFAULT_PBE_ALGORITHM = "PBEwithMD5andDES";

    private MaskedPasswordDecoder() {
    }

    /**
     * This decodes password encoded using {@code PBEUtils} class of PicketBox.
     *
     * Method ported from PicketBox to maintain backward compatibility.
     *
     * @param maskedString masked password string including (masked) prefix
     * @param salt salt
     * @param iterationCount iteration count
     * @param pbeAlgorithm PBE algorithm. {@code null} for default value.
     * @param initialKey initial key. {@code null} for default value.
     * @return returns clear text password
     * @throws Exception when anything goes wrong
     */
    public static char[] decode(final String maskedString, final String salt, final int iterationCount,
                                final String pbeAlgorithm, final String initialKey) throws Exception {

        String algorithm = pbeAlgorithm != null ? pbeAlgorithm : DEFAULT_PBE_ALGORITHM;
        String encryptedBase64EncodedSecret = maskedString.startsWith(PASS_MASK_PREFIX) ? maskedString.substring(PASS_MASK_PREFIX.length()) : maskedString;
        // Create the PBE secret key
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);

        char[] initialKeyMaterial = initialKey != null ? initialKey.toCharArray() : DEFAULT_PBE_KEY;
        PBEParameterSpec cipherSpec = new PBEParameterSpec(salt.getBytes(StandardCharsets.UTF_8), iterationCount);
        PBEKeySpec keySpec = new PBEKeySpec(initialKeyMaterial);
        SecretKey cipherKey = factory.generateSecret(keySpec);

        return decode64(encryptedBase64EncodedSecret, algorithm, cipherKey, cipherSpec).toCharArray();
    }

    private static String decode64(String secret, String cipherAlgorithm, SecretKey cipherKey, PBEParameterSpec cipherSpec)
            throws Exception {
        byte[] encoding;
        try {
            encoding = ByteIterator.ofBytes(secret.getBytes(StandardCharsets.UTF_8)).base64Decode(Alphabet.Base64Alphabet.PICKETBOX_BASE_64).drain();
        } catch (IllegalArgumentException e) {
            // fallback when original string is was created with faulty version of Base64
            String fallBack = "0" + secret;
            encoding = ByteIterator.ofBytes((fallBack).getBytes(StandardCharsets.UTF_8)).base64Decode().drain();
            log.warnWrongBase64EncodedString(fallBack);
        }
        byte[] decoded = decode(encoding, cipherAlgorithm, cipherKey, cipherSpec);

        return new String(decoded, StandardCharsets.UTF_8);
    }

    private static byte[] decode(byte[] secret, String cipherAlgorithm, SecretKey cipherKey, PBEParameterSpec cipherSpec)
            throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, cipherSpec);
        byte[] decode = cipher.doFinal(secret);
        return decode;
    }
}
