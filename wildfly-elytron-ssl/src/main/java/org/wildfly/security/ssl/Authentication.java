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
 * The authentication type for SSL/TLS cipher suite selection.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum Authentication {
    /**
     * No authentication (the cipher suite is anonymous).
     */
    NULL,
    /**
     * RSA key-based authentication.
     */
    RSA,
    /**
     * DSS key-based authentication.
     */
    DSS,
    /**
     * Diffie-Hellman key-based authentication.
     */
    DH,
    /**
     * Elliptic curve Diffie-Hellman key-based authentication.
     */
    ECDH,
    /**
     * Kerberos V5 authentication.
     */
    KRB5,
    /**
     * Elliptic curve DSA key-based authentication.
     */
    ECDSA,
    /**
     * Pre-shared key (PSK) based authentication.
     */
    PSK,
    /**
     * GOST R 34.10-94 authentication.
     */
    GOST94,
    /**
     * GOST R 34.10-2001 authentication.
     */
    GOST01,
    /**
     * Fortezza authentication.
     */
    FZA,
    ;
    static final int fullSize = values().length;

    static Authentication forName(final String name) {
        switch (name) {
            case "NULL": return NULL;
            case "RSA": return RSA;
            case "DSS": return DSS;
            case "DH": return DH;
            case "ECDH": return ECDH;
            case "KRB5": return KRB5;
            case "ECDSA": return ECDSA;
            case "PSK": return PSK;
            case "GOST94": return GOST94;
            case "GOST01": return GOST01;
            case "FZA": return FZA;
            default: return null;
        }
    }

    static Authentication require(final String name) {
        final Authentication authentication = forName(name);
        if (authentication == null) {
            throw log.unknownAuthenticationName(name);
        }
        return authentication;
    }

    /**
     * Determine whether the given set is "full" (meaning it contains all possible values).
     *
     * @param authentications the set
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<Authentication> authentications) {
        return authentications != null && authentications.size() == fullSize;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param value1 the first instance
     * @param value2 the second instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final Authentication value1, final Authentication value2) {
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
    public boolean in(final Authentication value1, final Authentication value2, final Authentication value3) {
        return this == value1 || this == value2 || this == value3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the values to match against
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final Authentication... values) {
        if (values != null) for (Authentication value : values) {
            if (this == value) return true;
        }
        return false;
    }
}
