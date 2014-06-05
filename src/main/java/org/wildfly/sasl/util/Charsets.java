/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.sasl.util;

import java.nio.charset.Charset;

/**
 * Character sets used by SASL protocols.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class Charsets {

    /**
     * The {@code UTF-8} character set.
     */
    public static final Charset UTF_8 = Charset.forName("UTF-8");

    /**
     * The {@code 8859_1} character set.
     */
    public static final Charset LATIN_1 = Charset.forName("8859_1");

    /**
     * Encode a string into UTF-8 (except encoding character zero to its two-byte form).
     *
     * @param src the source string
     * @param dest the array to encode to
     * @param offs the offset into the destination array
     * @return {@code true} if the string fit, {@code false} if it did not
     */
    public static boolean encodeTo(String src, byte[] dest, int offs) {
        final int srcLen = src.length();
        try {
            for (int i = 0; i < srcLen; i = src.offsetByCodePoints(i, 1)) {
                int cp = src.codePointAt(i);
                if (cp > 0 && cp <= 0x7f) {
                    // don't accidentally null-terminate the string
                    dest[offs ++] = (byte) cp;
                } else if (cp <= 0x07ff) {
                    dest[offs ++] = (byte)(0xc0 | 0x1f & cp >> 6);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp);
                } else if (cp <= 0xffff) {
                    dest[offs ++] = (byte)(0xe0 | 0x0f & cp >> 12);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 6);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp);
                } else if (cp <= 0x1fffff) {
                    dest[offs ++] = (byte)(0xf0 | 0x07 & cp >> 18);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 12);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 6);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp);
                } else if (cp <= 0x3ffffff) {
                    dest[offs ++] = (byte)(0xf8 | 0x03 & cp >> 24);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 18);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 12);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 6);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp);
                } else if (cp >= 0) {
                    dest[offs ++] = (byte)(0xfc | 0x01 & cp >> 30);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 24);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 18);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 12);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp >> 6);
                    dest[offs ++] = (byte)(0x80 | 0x3f & cp);
                } else {
                    // replacement char
                    dest[offs ++] = '?';
                }
            }
            return true;
        } catch (ArrayIndexOutOfBoundsException e) {
            return false;
        }
    }

    /**
     * Get the encoded length of a string.
     *
     * @param src the string
     * @return its encoded length
     */
    public static int encodedLengthOf(String src) {
        final int srcLen = src.length();
        int l = 0;
        for (int i = 0; i < srcLen; i = src.offsetByCodePoints(i, 1)) {
            int cp = src.codePointAt(i);
            if (cp > 0 && cp <= 0x7f) {
                // don't accidentally null-terminate the string
                l ++;
            } else if (cp <= 0x07ff) {
                l += 2;
            } else if (cp <= 0xffff) {
                l += 3;
            } else if (cp <= 0x1fffff) {
                l += 4;
            } else if (cp <= 0x3ffffff) {
                l += 5;
            } else if (cp >= 0) {
                l += 6;
            } else {
                // replacement char
                l ++;
            }
        }
        return l;
    }

    /**
     * Find the first occurrence of a byte in a byte array.
     *
     * @param array the array to search
     * @param search the byte to search for
     * @param offs the offset in the array to start searching
     * @param len the length of the segment to search
     * @return the index, or -1 if the byte is not found
     */
    public static int indexOf(byte[] array, int search, int offs, int len) {
        for (int i = 0; i < len; i ++) {
            if (array[offs + i] == (byte) search) {
                return offs + i;
            }
        }
        return -1;
    }

    /**
     * Find the first occurrence of a byte in a byte array.
     *
     * @param array the array to search
     * @param search the byte to search for
     * @param offs the offset in the array to start searching
     * @return the index, or -1 if the byte is not found
     */
    public static int indexOf(byte[] array, int search, int offs) {
        return indexOf(array, search, offs, array.length - offs);
    }

    /**
     * Find the first occurrence of a byte in a byte array.
     *
     * @param array the array to search
     * @param search the byte to search for
     * @return the index, or -1 if the byte is not found
     */
    public static int indexOf(byte[] array, int search) {
        return indexOf(array, search, 0, array.length);
    }

    private Charsets() {
    }
}
