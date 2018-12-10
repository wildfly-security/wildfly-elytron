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

package org.wildfly.security.sasl.gs2;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.codec.Base32Alphabet;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.auth.util.GSSCredentialSecurityFactory;

/**
 * Constants and utility methods for the GS2 mechanism family.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class Gs2 {

    public static final String GS2_PREFIX = "GS2-";
    public static final String PLUS_SUFFIX = "-PLUS";

    // Non-OID-derived mechanism names
    public static final String GS2_KRB5 = "GS2-KRB5";
    public static final String GS2_KRB5_PLUS = "GS2-KRB5-PLUS";

    // SPNEGO must not be used as a GS2 mechanism
    public static final String SPNEGO = "SPNEGO";
    public static final String SPNEGO_PLUS = "SPNEGO-PLUS";

    /**
     * Get the SASL mechanism name that corresponds to the given GSS-API mechanism object identifier.
     *
     * @param mechanismOid the object identifier for the GSS-API mechanism
     * @param plus {@code true} if the PLUS-variant of the SASL mechanism name should be returned and
     * {@code false} otherwise
     * @return the SASL mechanism name that corresponds to the given object identifier
     * @throws GSSException if the given object identifier cannot be mapped to a SASL name
     */
    public static String getSaslNameForMechanism(Oid mechanismOid, boolean plus) throws GSSException {
        if (mechanismOid == null) {
            throw new GSSException(GSSException.BAD_MECH);
        }

        // Non-OID-derived SASL mechanism names
        if (mechanismOid.equals(GSSCredentialSecurityFactory.KERBEROS_V5)) {
            if (plus) {
                return GS2_KRB5_PLUS;
            } else {
                return GS2_KRB5;
            }
        }
        if (mechanismOid.equals(GSSCredentialSecurityFactory.SPNEGO)) {
            if (plus) {
                return SPNEGO_PLUS;
            } else {
                return SPNEGO;
            }
        }

        // The SASL mechanism name is the concatenation of the string "GS2-" and the Base32 encoding of
        // the first 55 bits of the binary SHA-1 hash string computed over the ASN.1 DER encoding of the
        // GSS-API mechanism's OID
        ByteStringBuilder name = new ByteStringBuilder();
        name.append(GS2_PREFIX);
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new GSSException(GSSException.FAILURE);
        }
        messageDigest.update(mechanismOid.getDER());
        byte[] digest = messageDigest.digest();
        digest[6] &= 0xfe;
        String encoded = ByteIterator.ofBytes(digest, 0, 7).base32Encode(Base32Alphabet.STANDARD, false).drainToString();
        name.append(encoded.substring(0, encoded.length() - 1));
        if (plus) {
            name.append(PLUS_SUFFIX);
        }
        return new String(name.toArray(), StandardCharsets.UTF_8);
    }

    /**
     * Get the SASL mechanism name that corresponds to the given GSS-API mechanism object identifier.
     *
     * @param mechanismOid the object identifier for the GSS-API mechanism
     * @return the non-PLUS SASL mechanism name that corresponds to the given object identifier
     * @throws GSSException if the given object identifier cannot be mapped to a SASL name
     */
    public static String getSaslNameForMechanism(Oid mechanismOid) throws GSSException {
        return getSaslNameForMechanism(mechanismOid, false);
    }

    /**
     * Get the GSS-API mechanism object identifier that corresponds to the given SASL mechanism name.
     *
     * @param saslMechanismName the SASL mechanism name
     * @return the object identifier for the GSS-API mechanism that corresponds to the given SASL
     * mechanism name
     * @throws GSSException if the given SASL name cannot be mapped to an object identifier
     */
    public static Oid getMechanismForSaslName(GSSManager gssManager, String saslMechanismName) throws GSSException {
        int plusSuffixIndex = saslMechanismName.indexOf(PLUS_SUFFIX);
        if (plusSuffixIndex != -1) {
            saslMechanismName = saslMechanismName.substring(0, plusSuffixIndex);
        }
        if (saslMechanismName.equals(GS2_KRB5)) {
            return GSSCredentialSecurityFactory.KERBEROS_V5;
        }
        if (saslMechanismName.equals(SPNEGO)) {
            return GSSCredentialSecurityFactory.SPNEGO;
        }
        Oid[] mechanisms = gssManager.getMechs();
        if (mechanisms == null) {
            throw new GSSException(GSSException.BAD_MECH);
        }
        for (Oid mechanism : mechanisms) {
            if (getSaslNameForMechanism(mechanism).equals(saslMechanismName)) {
                return mechanism;
            }
        }
        throw new GSSException(GSSException.BAD_MECH);
    }
}
