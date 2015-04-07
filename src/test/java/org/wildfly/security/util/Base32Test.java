/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.wildfly.security.util.Alphabet.Base32Alphabet;

/**
 * Tests for Base32 encoding and decoding.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class Base32Test {

    @Test
    public void testEncodeEmpty() {
        // With the padding characters included
        CodePointIterator ci = CodePointIterator.ofString("").asLatin1().base32Encode();
        String encoded = ci.drainToString();
        assertEquals("", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);

        // Without the padding characters
        ci = CodePointIterator.ofString("").asLatin1().base32Encode(Base32Alphabet.STANDARD, false);
        encoded = ci.drainToString();
        assertEquals("", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncode6Padding() {
        // With the padding characters included
        CodePointIterator ci = CodePointIterator.ofString("f").asLatin1().base32Encode();
        String encoded = ci.drainToString();
        assertEquals("MY======", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);

        // Without the padding characters
        ci = CodePointIterator.ofString("f").asLatin1().base32Encode(Base32Alphabet.STANDARD, false);
        encoded = ci.drainToString();
        assertEquals("MY", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncode4Padding() {
        // With the padding characters included
        CodePointIterator ci = CodePointIterator.ofString("fo").asLatin1().base32Encode();
        String encoded = ci.drainToString();
        assertEquals("MZXQ====", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);

        // Without the padding characters
        ci = CodePointIterator.ofString("fo").asLatin1().base32Encode(Base32Alphabet.STANDARD, false);
        encoded = ci.drainToString();
        assertEquals("MZXQ", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncode3Padding() {
        // With the padding characters included
        CodePointIterator ci = CodePointIterator.ofString("foo").asLatin1().base32Encode();
        String encoded = ci.drainToString();
        assertEquals("MZXW6===", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);

        // Without the padding characters
        ci = CodePointIterator.ofString("foo").asLatin1().base32Encode(Base32Alphabet.STANDARD, false);
        encoded = ci.drainToString();
        assertEquals("MZXW6", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncode1Padding() {
        // With the padding characters included
        CodePointIterator ci = CodePointIterator.ofString("foob").asLatin1().base32Encode();
        String encoded = ci.drainToString();
        assertEquals("MZXW6YQ=", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);

        // Without the padding characters
        ci = CodePointIterator.ofString("foob").asLatin1().base32Encode(Base32Alphabet.STANDARD, false);
        encoded = ci.drainToString();
        assertEquals("MZXW6YQ", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeNoPadding() {
        // With the padding characters included
        CodePointIterator ci = CodePointIterator.ofString("fooba").asLatin1().base32Encode();
        String encoded = ci.drainToString();
        assertEquals("MZXW6YTB", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);

        // Without the padding characters
        ci = CodePointIterator.ofString("fooba").asLatin1().base32Encode(Base32Alphabet.STANDARD, false);
        encoded = ci.drainToString();
        assertEquals("MZXW6YTB", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    @Test
    public void testEncodeMoreThan5Characters() {
        // With the padding characters included
        CodePointIterator ci = CodePointIterator.ofString("foobarfoobarfoobar").asLatin1().base32Encode();
        String encoded = ci.drainToString();
        assertEquals("MZXW6YTBOJTG633CMFZGM33PMJQXE===", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);

        // Without the padding characters
        ci = CodePointIterator.ofString("foobarfoobarfoobar").asLatin1().base32Encode(Base32Alphabet.STANDARD, false);
        encoded = ci.drainToString();
        assertEquals("MZXW6YTBOJTG633CMFZGM33PMJQXE", encoded);
        verifyBackwardIterationOfEncodedCharacters(ci, encoded);
    }

    private void verifyBackwardIterationOfEncodedCharacters(CodePointIterator ci, String encoded) {
        int encodedSize = encoded.length();
        for (int i = encodedSize - 1; i >= 0; i--) {
            assertTrue(ci.hasPrev());
            assertEquals(encoded.charAt(i), ci.prev());
        }
    }
}
