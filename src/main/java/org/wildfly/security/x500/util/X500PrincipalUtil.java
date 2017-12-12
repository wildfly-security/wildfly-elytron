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

package org.wildfly.security.x500.util;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.asn1.util.ASN1.IA5_STRING_TYPE;
import static org.wildfly.security.asn1.util.ASN1.PRINTABLE_STRING_TYPE;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Decoder;
import org.wildfly.security.asn1.DERDecoder;

/**
 * A utility class for easily accessing details of an {@link X500Principal}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500PrincipalUtil {

    private static final String[] NO_STRINGS = new String[0];
    private static final Class<?> X500_NAME_CLASS;
    private static final MethodHandle AS_X500_PRINCIPAL_HANDLE;

    static {
        Class<?> x500Name = null;
        MethodHandle asX500PrincipalHandle = null;
        try {
            x500Name = Class.forName("sun.security.x509.X500Name", true, X500PrincipalUtil.class.getClassLoader());
            asX500PrincipalHandle = MethodHandles.publicLookup().unreflect(x500Name.getDeclaredMethod("asX500Principal"));
        } catch (Throwable t) {
            /*
             * This is intended to be a best efforts optimisation, if it fails for ANY reason we don't support the optimisation
             * and resort to default behaviour.
             *
             * Throwing any Exception or Error from this static block results in a NoClassDefFoundError for any access to the
             * class and subsequently even the non-optimised scenario is unavailable.
             */
            log.trace("X550Name.asX500Principal() is not available.", t);
        }

        X500_NAME_CLASS = x500Name;
        AS_X500_PRINCIPAL_HANDLE = asX500PrincipalHandle;
    }

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
        return getAttributeValues(principal, oid, false);
    }

    /**
     * Get all the values of the attribute with the given OID in the given principal.  This includes occurrences within
     * multi-valued RDNs.
     *
     * @param principal the principal to examine
     * @param oid the OID whose values are to be returned
     * @param reverse {@code true} if the values in the returned list should be in reverse order
     * @return the list of values associated with the OID
     */
    public static String[] getAttributeValues(X500Principal principal, String oid, boolean reverse) {
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
            throw log.unexpectedTrailingGarbageInX500principal();
        }
        String[] result = len == 0 ? NO_STRINGS : new String[len];
        if (! reverse) {
            // The attribute values will be in the same order they appear in the string representation of the X.500 principal
            for (int i = 0; i < len; i++) {
                result[len - i - 1] = strings[i];
            }
        } else {
            // The attribute values will be in reverse order
            for (int i = 0; i < len; i++) {
                result[i] = strings[i];
            }
        }
        return result;
    }

    /**
     * Determine if the given principal contains all of the attributes specified by the given OIDs.
     * This includes occurrences within multi-valued RDNs.
     *
     * @param principal the principal to examine
     * @param oids the OIDs of the attributes that must be present in the given principal (must not be {@code null},
     *  cannot have {@code null} elements)
     * @return {@code true} if the given principal contains all of the attributes specified by the given OIDs,
     *  {@code false} otherwise
     */
    public static boolean containsAllAttributes(X500Principal principal, String... oids) {
        Assert.checkNotNullParam("principal", principal);
        Assert.checkNotNullParam("oids", oids);
        final Set<String> requiredAttributes = new HashSet<>(Arrays.asList(oids));
        final ASN1Decoder decoder = new DERDecoder(principal.getEncoded());
        decoder.startSequence();
        while (decoder.hasNextElement() && ! requiredAttributes.isEmpty()) {
            decoder.startSet();
            while (decoder.hasNextElement() && ! requiredAttributes.isEmpty()) {
                decoder.startSequence();
                // first item is the attribute
                String testOid = decoder.decodeObjectIdentifier();
                requiredAttributes.remove(testOid);
                // skip over the attribute value
                decoder.skipElement();
                decoder.endSequence();
            }
            decoder.endSet();
        }
        decoder.endSequence();
        if (decoder.hasNextElement()) {
            throw log.unexpectedTrailingGarbageInX500principal();
        }
        return requiredAttributes.isEmpty();
    }

    /**
     * Attempt to convert the given principal to an X.500 principal.
     *
     * @param principal the original principal
     * @return the X.500 principal or {@code null} if the principal can not be converted.
     */
    public static X500Principal asX500Principal(Principal principal) {
        return asX500Principal(principal, false);
    }

    /**
     * Attempt to convert the given principal to an X.500 principal.
     *
     * @param principal the original principal
     * @param convert {@code true} if the principal should be converted to a {@link X500Principal} if not one already.
     * @return the X.500 principal or {@code null} if the principal can not be converted.
     */
    public static X500Principal asX500Principal(Principal principal, boolean convert) {
        if (principal instanceof X500Principal) {
            return (X500Principal) principal;
        }
        if (X500_NAME_CLASS != null && X500_NAME_CLASS.isAssignableFrom(principal.getClass())) {
            try {
                return (X500Principal) AS_X500_PRINCIPAL_HANDLE.invoke(principal);
            } catch (RuntimeException | Error ex) {
                throw ex;
            } catch (Throwable t) {
                throw new UndeclaredThrowableException(t);
            }
        }
        if (convert) {
            try {
                return new X500Principal(principal.getName());
            } catch (IllegalArgumentException ignored) {
                log.trace("Unable to convert to X500Principal", ignored);
            }
        }

        return null;
    }
}
