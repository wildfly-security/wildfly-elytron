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

package org.wildfly.security.x500;

import static org.wildfly.security.asn1.ASN1.*;

import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.asn1.ASN1Decoder;
import org.wildfly.security.asn1.DERDecoder;

/**
 * A utility class for easily accessing details of an {@link X500Principal}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500PrincipalUtil {

    private static final String[] NO_STRINGS = new String[0];

    private X500PrincipalUtil() {
    }

    /**
     * Get all the values of the attribute with the given OID in the given principal.  This includes occurrences within
     * multi-valued RDNs.
     *
     * @param principal the principal to examine
     * @param oid the OID whose values are to be returned
     * @return the list of values associated with the OID
     */
    public static String[] getAttributeValues(X500Principal principal, String oid) {
        final ASN1Decoder decoder = new DERDecoder(principal.getEncoded());
        String[] strings = NO_STRINGS;
        int len = 0;
        decoder.startSequence();
        while (decoder.hasNextElement()) {
            decoder.startSet();
            while (decoder.hasNextElement()) {
                decoder.startSequence();
                // first item is the attribute
                String testOid = decoder.decodeObjectIdentifier();
                if (oid.equals(testOid)) {
                    // second item is the value
                    switch (decoder.peekType()) {
                        case IA5_STRING_TYPE: {
                            if (strings.length == len) {
                                strings = Arrays.copyOf(strings, Math.max(2, strings.length) * 2);
                            }
                            strings[len++] = decoder.decodeIA5String();
                            break;
                        }
                        case PRINTABLE_STRING_TYPE: {
                            if (strings.length == len) {
                                strings = Arrays.copyOf(strings, Math.max(2, strings.length) * 2);
                            }
                            strings[len++] = decoder.decodePrintableString();
                            break;
                        }
                        default: {
                            decoder.skipElement();
                            break;
                        }
                    }
                } else {
                    decoder.skipElement();
                }
                decoder.endSequence();
            }
            decoder.endSet();
        }
        decoder.endSequence();
        if (decoder.hasNextElement()) {
            throw new IllegalArgumentException("Unexpected trailing garbage in X.500 principal");
        }
        String[] result = len == 0 ? NO_STRINGS : new String[len];
        for (int i = 0; i < len; i ++) {
            result[len - i - 1] = strings[i];
        }
        return result;
    }
}
