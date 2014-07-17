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

package org.wildfly.sasl.test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.wildfly.sasl.util.ByteStringBuilder;
import org.wildfly.sasl.util.SaslBase64;

/**
 * Tests for SaslBase64 utility methods.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public class SaslBase64TestCase {

    /**
     * Tests if encoding/decoding works properly.
     * (data length) % 3 == 0
     */
    @Test
    public void testEcodeDecodeToByteStringBuilderMod0() {
        doEncodeDecodeTest(generateData(255));
    }

    /**
     * Tests if encoding/decoding works properly.
     * (data length) % 3 == 0
     */
    @Test
    public void testEcodeDecodeToByteStringBuilderMod1() {
        doEncodeDecodeTest(generateData(256));
    }

    /**
     * Tests if encoding/decoding works properly.
     * (data length) % 3 == 0
     */
    @Test
    public void testEcodeDecodeToByteStringBuilderMod2() {
        doEncodeDecodeTest(generateData(253));
    }

    private void doEncodeDecodeTest(byte[] inputData) {
        ByteStringBuilder bsb = new ByteStringBuilder();
        SaslBase64.encode(inputData, bsb);

        byte[] result = bsb.toArray();
        assertTrue("Whole result data has to be within the range for base64", isInRange(result));
        assertEncodedLength(inputData.length, result.length);

        ByteStringBuilder afterDecode = new ByteStringBuilder();
        SaslBase64.decode(result, 0, afterDecode);

        assertArrayEquals("Encode-Decode test failed, results are not the same.", inputData, afterDecode.toArray());
    }

    private boolean isInRange(byte[] data) {
        boolean allMembersInRange = true;
        for (int i = 0; i < data.length; i++) {
            if (data[i] == '=') {
                if ((i != data.length - 1) && (i != data.length - 2)) {
                    allMembersInRange = false;
                }
            } else {
                if (!((data[i] >= 'A' && data[i] <= 'Z') || (data[i] >= 'a' && data[i] <= 'z')
                        || (data[i] >= '0' && data[i] <= '9') || data[i] == '+' || data[i] == '/')) {
                    allMembersInRange = false;
                }
            }
        }
        return allMembersInRange;
    }

    private void assertEncodedLength(int originalLen, int encodedLen) {

        int expectedLen;
        if (originalLen % 3 != 0) {
            expectedLen = (originalLen/3 + 1) * 4;
        } else {
            expectedLen = originalLen/3 * 4;
        }

        assertTrue("Encoded data are too long for base64 encoding ", encodedLen <= expectedLen);
    }

    private byte[] generateData(final int len) {
        byte[] data = new byte[len];
        for (int i = 0; i < len ; i++) {
            data[i] = (byte)i;
        }
        return data;
    }

}
