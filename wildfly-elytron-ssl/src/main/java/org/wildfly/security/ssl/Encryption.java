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

package org.wildfly.security.ssl;

import static org.wildfly.security.ssl.ElytronMessages.log;

import java.util.EnumSet;

/**
 * The encryption type for SSL/TLS cipher suite selection.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum Encryption {
    /**
     * No encryption.
     */
    NULL,
    /**
     * AES encryption with 256-bit keys in Galois counter mode (GCM).
     */
    AES256GCM,
    /**
     * AES encryption with 256-bit keys in CBC-MAC Mode (CCM).
     */
    AES256CCM,
    /**
     * AES encryption with 256-bit keys in CBC-MAC Mode (CCM) with an 8-Octet Integrity Check Value.
     */
    AES256CCM8,
    /**
     * AES encryption with 256-bit keys.
     */
    AES256,
    /**
     * AES encryption with 128-bit keys in Galois counter mode (GCM).
     */
    AES128GCM,
    /**
     * AES encryption with 128-bit keys in CBC-MAC Mode (CCM).
     */
    AES128CCM,
    /**
     * AES encryption with 128-bit keys in CBC-MAC Mode (CCM) with an 8-Octet Integrity Check Value.
     */
    AES128CCM8,
    /**
     * AES encryption with 128-bit keys.
     */
    AES128,
    /**
     * Camellia encryption with 256-bit keys.
     */
    CAMELLIA256,
    /**
     * Camellia encryption with 128-bit keys.
     */
    CAMELLIA128,
    /**
     * Triple-DES encryption.
     */
    _3DES,
    /**
     * Simple DES encryption.
     */
    DES,
    /**
     * IDEA encryption.
     */
    IDEA,
    /**
     * GOST 28147-89 encryption as defined in <a href="https://tools.ietf.org/html/rfc5830">RFC 5830</a>.
     */
    GOST2814789CNT,
    /**
     * SEED encryption.
     */
    SEED,
    /**
     * Fortezza encryption.
     */
    FZA,
    /**
     * RC4 encryption.
     */
    RC4,
    /**
     * RC2 encryption.
     */
    RC2,
    /**
     * ChaCha20 encryption.
     */
    CHACHA20,
    /**
     * ARIA encryption with 256-bit keys in Galois counter mode (GCM).
     */
    ARIA256GCM,
    /**
     * ARIA encryption with 256-bit keys.
     */
    ARIA256,
    /**
     * ARIA encryption with 128-bit keys in Galois counter mode (GCM).
     */
    ARIA128GCM,
    /**
     * ARIA encryption with 128-bit.
     */
    ARIA128
    ;

    /**
     * Legacy name for {@link #CHACHA20}.
     *
     * @deprecated Use {@link #CHACHA20} instead.
     */
    @Deprecated
    public static final Encryption CHACHA20POLY1305 = CHACHA20;

    static final int fullSize = values().length;

    static Encryption forName(final String name) {
        switch (name) {
            case "NULL": return NULL;
            case "AES256GCM": return AES256GCM;
            case "AES256CCM": return AES256CCM;
            case "AES256CCM8": return AES256CCM8;
            case "AES256": return AES256;
            case "AES128GCM": return AES128GCM;
            case "AES128CCM": return AES128CCM;
            case "AES128CCM8": return AES128CCM8;
            case "AES128": return AES128;
            case "CAMELLIA256": return CAMELLIA256;
            case "CAMELLIA128": return CAMELLIA128;
            case "CHACHA20POLY1305": // fall through
            case "CHACHA20": return CHACHA20;
            case "3DES": return _3DES;
            case "DES": return DES;
            case "IDEA": return IDEA;
            case "GOST2814789CNT": return GOST2814789CNT;
            case "SEED": return SEED;
            case "FZA": return FZA;
            case "RC4": return RC4;
            case "RC2": return RC2;
            case "ARIA256GCM": return ARIA256GCM;
            case "ARIA256": return ARIA256;
            case "ARIA128GCM": return ARIA128GCM;
            case "ARIA128": return ARIA128;
            default: return null;
        }
    }

    static Encryption require(final String name) {
        final Encryption encryption = forName(name);
        if (encryption == null) {
            throw log.unknownEncryptionName(name);
        }
        return null;
    }

    /**
     * Determine whether the given set is "full" (meaning it contains all possible values).
     *
     * @param encryptions the set
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<Encryption> encryptions) {
        return encryptions != null && encryptions.size() == fullSize;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param value1 the first instance
     * @param value2 the second instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final Encryption value1, final Encryption value2) {
        return this == value1 || this == value2;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param value1 the first instance
     * @param value2 the second instance
     * @param value3 the third instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final Encryption value1, final Encryption value2, final Encryption value3) {
        return this == value1 || this == value2 || this == value3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the values to match against
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final Encryption... values) {
        if (values != null) for (Encryption value : values) {
            if (this == value) return true;
        }
        return false;
    }
}
