/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.x500.cert;

import java.util.EnumSet;

/**
 * The various key usage types.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum KeyUsage {
    // Do not re-order
    digitalSignature,
    nonRepudiation,
    keyEncipherment,
    dataEncipherment,
    keyAgreement,
    keyCertSign,
    cRLSign,
    encipherOnly,
    decipherOnly,
    ;

    static final int fullSize = values().length;

    /**
     * Determine whether the given set is fully populated (or "full"), meaning it contains all possible values.
     *
     * @param set the set
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<KeyUsage> set) {
        return set != null && set.size() == fullSize;
    }

    /**
     * Determine whether the bit # corresponding to this enumeration is set in the given boolean array.
     *
     * @param booleans the boolean array (must not be {@code null})
     * @return {@code true} if there is a {@code true} {@code boolean} at the index corresponding to the ordinal of this constant
     */
    public boolean in(final boolean[] booleans) {
        final int ordinal = ordinal();
        return booleans.length > ordinal && booleans[ordinal];
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final KeyUsage v1) {
        return this == v1;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final KeyUsage v1, final KeyUsage v2) {
        return this == v1 || this == v2;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param v1 the first instance
     * @param v2 the second instance
     * @param v3 the third instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final KeyUsage v1, final KeyUsage v2, final KeyUsage v3) {
        return this == v1 || this == v2 || this == v3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the possible values
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final KeyUsage... values) {
        if (values != null) for (KeyUsage value : values) {
            if (this == value) return true;
        }
        return false;
    }

    static KeyUsage forName(final String name) {
        switch (name) {
            case "digitalSignature": return digitalSignature;
            case "nonRepudiation": return nonRepudiation;
            case "keyEncipherment": return keyEncipherment;
            case "dataEncipherment": return dataEncipherment;
            case "keyAgreement": return keyAgreement;
            case "keyCertSign": return keyCertSign;
            case "cRLSign": return cRLSign;
            case "encipherOnly": return encipherOnly;
            case "decipherOnly": return decipherOnly;
            default: return null;
        }
    }

}
