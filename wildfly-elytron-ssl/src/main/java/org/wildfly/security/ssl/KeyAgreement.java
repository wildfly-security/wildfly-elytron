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
 * The key agreement type for SSL/TLS cipher suite selection.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public enum KeyAgreement {
    /**
     * Ephemeral elliptic-curve Diffie-Hellman key agreement.
     */
    ECDHE,
    /**
     * RSA key agreement.
     */
    RSA,
    /**
     * Diffie-Hellman key agreement using RSA-signed keys.
     */
    DHr,
    /**
     * Diffie-Hellman key agreement using DSS-signed keys.
     */
    DHd,
    /**
     * Ephemeral Diffie-Hellman key agreement.
     */
    DHE,
    /**
     * Pre-shared key ("PSK") key agreement.
     */
    PSK,
    /**
     * Fortezza key agreement.
     */
    FZA,
    /**
     * Kerberos V5 key agreement.
     */
    KRB5,
    /**
     * Elliptic-curve Diffie-Hellman ("ECDH") key agreement using RSA-signed keys.
     */
    ECDHr,
    /**
     * Elliptic-curve Diffie-Hellman ("ECDH") key agreement using ECDH-signed keys.
     */
    ECDHe,
    /**
     * VKA 34.10 key agreement as per <a href="https://tools.ietf.org/html/rfc4357">RFC 4357</a>.
     */
    GOST,
    /**
     * Secure remote password ("SRP") key agreement as per <a href="http://tools.ietf.org/html/rfc5054">RFC 5054</a>.
     */
    SRP,
    /**
     * RSA pre-shared key ("PSK") key agreement.
     */
    RSAPSK,
    /**
     * Ephemeral Diffie-Hellman pre-shared key ("PSK") key agreement.
     */
    DHEPSK,
    /**
     * RSA pre-shared key ("PSK") key agreement.
     */
    ECDHEPSK,
    ;
    static final int fullSize = values().length;

    static KeyAgreement forName(final String name) {
        switch (name) {
            case "EECDH": case "ECDHE": return ECDHE;
            case "RSA": return RSA;
            case "DHr": return DHr;
            case "DHd": return DHd;
            case "EDH": case "DHE": return DHE;
            case "PSK": return PSK;
            case "FZA": return FZA;
            case "KRB5": return KRB5;
            case "ECDHr": return ECDHr;
            case "ECDHe": return ECDHe;
            case "GOST": return GOST;
            case "SRP": return SRP;
            case "RSAPSK": return RSAPSK;
            case "EDHPSK": case "DHEPSK": return DHEPSK;
            case "ECDHEPSK": case "EECDHPSK": return ECDHEPSK;
            default: return null;
        }
    }

    static KeyAgreement require(final String name) {
        final KeyAgreement keyAgreement = forName(name);
        if (keyAgreement == null) {
            throw log.unknownKeyExchangeName(name);
        }
        return keyAgreement;
    }

    /**
     * Determine whether the given set is "full" (meaning it contains all possible values).
     *
     * @param keyAgreements the set
     * @return {@code true} if the set is full, {@code false} otherwise
     */
    public static boolean isFull(final EnumSet<KeyAgreement> keyAgreements) {
        return keyAgreements != null && keyAgreements.size() == fullSize;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param value1 the first instance
     * @param value2 the second instance
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final KeyAgreement value1, final KeyAgreement value2) {
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
    public boolean in(final KeyAgreement value1, final KeyAgreement value2, final KeyAgreement value3) {
        return this == value1 || this == value2 || this == value3;
    }

    /**
     * Determine whether this instance is equal to one of the given instances.
     *
     * @param values the values to match against
     * @return {@code true} if one of the instances matches this one, {@code false} otherwise
     */
    public boolean in(final KeyAgreement... values) {
        if (values != null) for (KeyAgreement value : values) {
            if (this == value) return true;
        }
        return false;
    }
}
