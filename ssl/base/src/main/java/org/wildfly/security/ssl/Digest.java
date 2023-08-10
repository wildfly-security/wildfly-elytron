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

import java.util.EnumSet;

/**
 * The digest algorithm type for SSL/TLS cipher suite selection.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum Digest {
    /**
     * The MD5 digest algorithm.
     */
    MD5,
    /**
     * The SHA-1 digest algorithm.
     */
    SHA1,
    /**
     * The GOST R 34.11-94 (HMAC) digest algorithm.
     */
    GOST94,
    /**
     * The GOST 28147-89 (MAC, not HMAC) digest algorithm.
     */
    GOST89MAC,
    /**
     * The SHA-256 digest algorithm.
     */
    SHA256,
    /**
     * The SHA-384 digest algorithm.
     */
    SHA384,
    /**
     * AEAD (Authenticated Encryption with Associated Data) based authenticated message mode.
     *
     * @deprecated no longer used; refer to the actual digest algorithm instead.
     */
    @Deprecated
    AEAD,
    ;
    static final int fullSize = values().length;

    static Digest forName(final String name) {
        switch (name) {
            case "MD5": return MD5;
            case "SHA1": return SHA1;
            case "GOST94": return GOST94;
            case "GOST89MAC": return GOST89MAC;
            case "SHA256": return SHA256;
            case "SHA384": return SHA384;
            case "AEAD": return AEAD;
            default: return null;
        }
    }

    /**
     * Determine whether the given set is "full" (meaning it contains all possible values).
     *
     * @param digests the set
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<Digest> digests) {
        return digests != null && digests.size() == fullSize;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param value1 the first instance
     * @param value2 the second instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final Digest value1, final Digest value2) {
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
    public boolean in(final Digest value1, final Digest value2, final Digest value3) {
        return this == value1 || this == value2 || this == value3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the values to match against
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final Digest... values) {
        if (values != null) for (Digest value : values) {
            if (this == value) return true;
        }
        return false;
    }
}
