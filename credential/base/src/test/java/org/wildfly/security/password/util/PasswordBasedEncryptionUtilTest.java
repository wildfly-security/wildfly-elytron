/*
 * JBoss, Home of Professional Open Source
 * Copyright 2019 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.password.util;

import java.security.GeneralSecurityException;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.common.codec.Alphabet;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

/**
 * ModularCrypt alphabets section of tests for PasswordBasedEncryptionUtil
 * See org.wildfly.security.util.PasswordBasedEncryptionUtilTest for the rests of the tests
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class PasswordBasedEncryptionUtilTest {

    private static final String clearText = "Červenavý střizlíček a štebotavá žlůva ďobali ve sťavnatých ocúnech.";

    /**
     * Test pair of encrypt/decrypt methods with Base32/Base64 encodings as input/output.
     * @throws GeneralSecurityException when something goes wrong
     */
    @Test
    public void testEncryptEncode() throws GeneralSecurityException {

        String[] algorithms = {"PBEWithHmacSHA1andAES_128","PBEWithHmacSHA256AndAES_128","PBEWithMD5AndDES"};

        Alphabet[] alphabets = {
                ModularCrypt.BCRYPT,
                ModularCrypt.MOD_CRYPT,
                ModularCrypt.MOD_CRYPT_LE
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
}
