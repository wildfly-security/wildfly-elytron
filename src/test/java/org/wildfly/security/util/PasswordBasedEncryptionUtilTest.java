/*
 * JBoss, Home of Professional Open Source
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.util;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.common.codec.Alphabet;
import org.wildfly.common.codec.Base32Alphabet;
import org.wildfly.common.codec.Base64Alphabet;
import org.wildfly.security.password.util.ModularCrypt;

/**
 * Tests for PasswordBasedEncryptionUtil class.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class PasswordBasedEncryptionUtilTest {

    private static final String clearText = "Červenavý střizlíček a štebotavá žlůva ďobali ve sťavnatých ocúnech.";
    private static final String DEFAULT_PICKETBOX_ALGORITHM = "PBEWithMD5AndDES";
    private static final String DEFAULT_PICKETBOX_INITIAL_KEY_MATERIAL = "somearbitrarycrazystringthatdoesnotmatter";

    /**
     * Test pair of encrypt/decrypt methods with Base32/Base64 encodings as input/output.
     * @throws GeneralSecurityException when something goes wrong
     */
    @Test
    public void testEncryptEncode() throws GeneralSecurityException {

        String[] algorithms = {"PBEWithHmacSHA1andAES_128","PBEWithHmacSHA256AndAES_128","PBEWithMD5AndDES"};

        Alphabet[] alphabets = {
            Base64Alphabet.STANDARD,
            PasswordBasedEncryptionUtil.PICKETBOX_COMPATIBILITY,
            ModularCrypt.BCRYPT,
            ModularCrypt.MOD_CRYPT,
            ModularCrypt.MOD_CRYPT_LE,
            Base32Alphabet.STANDARD,
        };

        for(String algorithm : algorithms) {
            for (Alphabet alphabet: alphabets) {
                doEncryptEncode(algorithm, "WHOLE", alphabet);
                doEncryptEncode(algorithm, "IV", alphabet);
            }
        }

    }

    private void doEncryptEncode(String algorithm, String transferAlgParams, Alphabet alphabet) throws GeneralSecurityException {

        String params = String.format("[algorithm=%s, transferAlgParams=%s]", algorithm, transferAlgParams);

        PasswordBasedEncryptionUtil pbeUtil1 =
                new PasswordBasedEncryptionUtil.Builder()
                        .alphabet(alphabet)
                        .password("ThisIsStrangeInitialKey")
                        .salt("SALTsalt")
                        .iteration(234)
                        .keyAlgorithm(algorithm)
                        .encryptMode().build();

        PasswordBasedEncryptionUtil.Builder builder2 =
                new PasswordBasedEncryptionUtil.Builder()
                        .password("ThisIsStrangeInitialKey")
                        .salt("SALTsalt")
                        .iteration(234)
                        .alphabet(alphabet)
                        .keyAlgorithm(algorithm)
                        .decryptMode();

        if ("WHOLE".equals(transferAlgParams)) {
            builder2.algorithmParameters(pbeUtil1.getAlgorithmParameters());
        } else if ("IV".equals(transferAlgParams)) {
            builder2.iv(pbeUtil1.getEncodedIV());
        }

        PasswordBasedEncryptionUtil pbeUtil2 = builder2.build();

        String encodedSecret = pbeUtil1.encryptAndEncode(clearText.toCharArray());
        Assert.assertNotNull("encodedSecret is supposed to be not null (" + params + ")", encodedSecret);
        char[] decrypted = pbeUtil2.decodeAndDecrypt(encodedSecret);
        Assert.assertNotNull("decrypted is supposed to be not null (" + params + ")", decrypted);
        Assert.assertArrayEquals("clearText should be equal decrypted (" + params + ")", clearText.toCharArray(), decrypted);
    }


    /**
     * Test pair of encrypt/decrypt methods with PBKDF2 key generating algorithm.
     * @throws GeneralSecurityException when something goes wrong
     */
    @Test
    public void testPBKDF() throws GeneralSecurityException {

        String keyAlgorithm = "PBKDF2WithHmacSHA1";
        String transformation = "PBEWithHmacSHA256AndAES_128";
        String parameters = transformation;

        PasswordBasedEncryptionUtil pbeUtil1 =
                new PasswordBasedEncryptionUtil.Builder()
                        .password("ThisIsStrangeInitialKey")
                        .salt("SALTsalt".getBytes(StandardCharsets.UTF_8))
                        .iteration(234)
                        .keyAlgorithm(keyAlgorithm)
                        .keyLength(256)
                        .transformation(transformation)
                        .parametersAlgorithm(parameters)
                        .cipherIteration(516)
                        .cipherSalt("frosty11".getBytes(StandardCharsets.UTF_8))
                        .encryptMode()
                        .build();

        PasswordBasedEncryptionUtil.Builder builder2 =
                new PasswordBasedEncryptionUtil.Builder()
                        .password("ThisIsStrangeInitialKey".toCharArray())
                        .salt("SALTsalt")
                        .iteration(234)
                        .keyAlgorithm(keyAlgorithm)
                        .keyLength(256)
                        .transformation(transformation)
                        .parametersAlgorithm(parameters)
                        .cipherIteration(516)
                        .cipherSalt("frosty11")
                        .decryptMode();

        builder2.iv(pbeUtil1.getEncodedIV());

        PasswordBasedEncryptionUtil pbeUtil2 = builder2.build();

        String encodedSecret = pbeUtil1.encryptAndEncode(clearText.toCharArray());
        Assert.assertNotNull("encodedSecret is supposed to be not null", encodedSecret);
        char[] decrypted = pbeUtil2.decodeAndDecrypt(encodedSecret);
        Assert.assertNotNull("decrypted is supposed to be not null", decrypted);
        Assert.assertArrayEquals("clearText should be equal decrypted", clearText.toCharArray(), decrypted);
    }

    /**
     * Test to check if PicketBox compatibility mode can produce and consume strings from PicketBox encoding.
     *
     * @throws Exception when something goes wrong
     */
    @Test
    public void testPicketBoxCompatibility() throws Exception {
        final String secret1 = "secret_password";
        final String pbGenerated1 = "1GhfMaq4jSY0.kFFU3QG4T";  // secret_password;12345678;230
        checkPb(secret1, "12345678", 230, pbGenerated1);

        final String secret2 = "super_secret";
        final String pbGenerated2 = "088WUKotOwu7VOS8xRj.Rr";  // super_secret;ASDF1234;123
        checkPb(secret2, "ASDF1234", 123, pbGenerated2);
    }

    private void checkPb(String secret, String salt, int iteration, String pbGenerated) throws GeneralSecurityException {

        PasswordBasedEncryptionUtil encryptUtil = new PasswordBasedEncryptionUtil.Builder()
                .picketBoxCompatibility()
                .salt(salt)
                .iteration(iteration)
                .encryptMode()
                .build();

        PasswordBasedEncryptionUtil decryptUtil = new PasswordBasedEncryptionUtil.Builder()
                .picketBoxCompatibility()
                .salt(salt)
                .iteration(iteration)
                .decryptMode()
                .build();

        String encrypted = encryptUtil.encryptAndEncode(secret.toCharArray());
        String crossDecrypted = new String(decryptUtil.decodeAndDecrypt(pbGenerated));
        String decrypted = new String(decryptUtil.decodeAndDecrypt(encrypted));

        Assert.assertTrue("Elytron in PB compatible mode failed", decrypted.equals(secret));
        Assert.assertTrue("PicketBox encrypted, Elytron decrypted in compatible mode, failed", crossDecrypted.equals(secret));
        Assert.assertTrue("Elytron in compatible mode encrypted, PicketBox encrypted must be the same", pbGenerated.equals(encrypted));

    }

}
