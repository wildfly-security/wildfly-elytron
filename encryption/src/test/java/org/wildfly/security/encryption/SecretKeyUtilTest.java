/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.encryption;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.wildfly.security.encryption.SecretKeyUtil.exportSecretKey;
import static org.wildfly.security.encryption.SecretKeyUtil.generateSecretKey;
import static org.wildfly.security.encryption.SecretKeyUtil.importSecretKey;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;

import static org.junit.Assert.assertNotEquals;



/**
 * Test Case for the {@code SecretKeyUtil} utility.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SecretKeyUtilTest {

    @Test
    public void testGenerateBadKeySize() {
        final int[] testSizes = new int[] { 0, 1, 127, 129, 191, 193, 255, 257 };
        for (int size : testSizes) {
            try {
                generateSecretKey(size);
                fail("Expected exception not thrown");
            } catch (Exception e) {
            }
        }
    }

    @Test
    public void testGenerateExportImport() throws Exception {
        final int[] testSizes = new int[] { 128, 192, 256 };
        for (int size : testSizes) {
            SecretKey original = generateSecretKey(size);
            assertNotNull("Expected SecretKey instance", original);
            String exported = exportSecretKey(original);
            assertNotNull("Export String", exported);
            SecretKey imported = importSecretKey(exported);
            assertNotNull("Expected SecretKey instance", imported);

            assertEquals("Matching keys", original, imported);

            SecretKey newKey = generateSecretKey(size);
            assertNotEquals("Keys should be different", imported, newKey);
        }
    }

    @Test(expected=IllegalArgumentException.class)
    public void testBadPrefix() throws Exception {
        SecretKey original = generateSecretKey(128);
        String exported = exportSecretKey(original);
        byte[] raw = CodePointIterator.ofString(exported).base64Decode().drain();
        raw[0] = 0x00;
        raw[1] = 0x00;
        raw[2] = 0x00;
        String encoded = ByteIterator.ofBytes(raw).base64Encode().drainToString();

        importSecretKey(encoded);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testBadVersion() throws Exception {
        SecretKey original = generateSecretKey(128);
        String exported = exportSecretKey(original);
        byte[] raw = CodePointIterator.ofString(exported).base64Decode().drain();
        raw[3] = SecretKeyUtil.VERSION + 1;  // We don't want to test all bad versions but do want to be sure the next version is automatically rejected.
        String encoded = ByteIterator.ofBytes(raw).base64Encode().drainToString();

        importSecretKey(encoded);
    }

}
