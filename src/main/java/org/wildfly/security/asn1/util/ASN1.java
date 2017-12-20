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

package org.wildfly.security.asn1.util;

import static org.wildfly.security._private.ElytronMessages.log;

import org.wildfly.security.asn1.ASN1Decoder;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.util._private.Arrays2;

/**
 * A class that contains ASN.1 constants and utilities.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ASN1 {

    /**
     * The universal boolean type tag.
     */
    public static final int BOOLEAN_TYPE = 1;

    /**
     * The universal integer type tag.
     */
    public static final int INTEGER_TYPE = 2;

    /**
     * The universal bit string type tag.
     */
    public static final int BIT_STRING_TYPE = 3;

    /**
     * The universal octet string type tag.
     */
    public static final int OCTET_STRING_TYPE = 4;

    /**
     * The universal null type tag.
     */
    public static final int NULL_TYPE = 5;

    /**
     * The universal object identifier type tag.
     */
    public static final int OBJECT_IDENTIFIER_TYPE = 6;

    /**
     * The universal UTF-8 string type tag.
     */
    public static final int UTF8_STRING_TYPE = 12;

    /**
     * The universal printable string type tag.
     */
    public static final int PRINTABLE_STRING_TYPE = 19;

    /**
     * The universal IA5 string type tag.
     */
    public static final int IA5_STRING_TYPE = 22;

    /**
     * A type for representing timestamps.
     */
    public static final int GENERALIZED_TIME_TYPE = 24;

    /**
     * The universal (UTF-32 big-endian) string type tag.
     */
    public static final int UNIVERSAL_STRING_TYPE = 28;

    /**
     * The universal BMP (UTF-16 big-endian) string type tag.
     */
    public static final int BMP_STRING_TYPE = 30;

    /**
     * The universal sequence type tag.
     */
    public static final int SEQUENCE_TYPE = 48;

    /**
     * The universal set type tag.
     */
    public static final int SET_TYPE = 49;

    /**
     * Mask used to determine if a type tag is constructed.
     */
    public static final int CONSTRUCTED_MASK = 0x20;

    /**
     * Mask used to determine if a type tag is application-specific.
     */
    public static final int APPLICATION_SPECIFIC_MASK = 0x40;

    /**
     * Mask used to determine if a type tag is context-specific.
     */
    public static final int CONTEXT_SPECIFIC_MASK = 0x80;

    /**
     * Mask used to obtain the class bits from a type tag.
     */
    public static final int CLASS_MASK = 0xc0;

    /**
     * Mask used to obtain the tag number bits from a type tag.
     */
    public static final int TAG_NUMBER_MASK = 0x1f;

    // 1.2.840.10040

    /**
     * Object identifier for the SHA1 with DSA signature algorithm.
     */
    public static final String OID_SHA1_WITH_DSA = "1.2.840.10040.4.3";

    /**
     * Object identifier for the SHA256 with DSA signature algorithm.
     *
     * @since 1.2.0
     */
    public static final String OID_SHA256_WITH_DSA = "2.16.840.1.101.3.4.3.2";

    // 1.2.840.10045

    /**
     * Object identifier for the SHA1 with ECDSA signature algorithm.
     */
    public static final String OID_SHA1_WITH_ECDSA = "1.2.840.10045.4.1";

    /**
     * Object identifier for the SHA-225 with ECDSA signature algorithm.
     */
    public static final String OID_SHA224_WITH_ECDSA = "1.2.840.10045.4.3.1";

    /**
     * Object identifier for the SHA-256 with ECDSA signature algorithm.
     */
    public static final String OID_SHA256_WITH_ECDSA = "1.2.840.10045.4.3.2";

    /**
     * Object identifier for the SHA-384 with ECDSA signature algorithm.
     */
    public static final String OID_SHA384_WITH_ECDSA = "1.2.840.10045.4.3.3";

    /**
     * Object identifier for the SHA-512 with ECDSA signature algorithm.
     */
    public static final String OID_SHA512_WITH_ECDSA = "1.2.840.10045.4.3.4";

    // 1.2.840.113549.1

    /**
     * Object identifier for the MD2 with RSA signature algorithm.
     */
    public static final String OID_MD2_WITH_RSA = "1.2.840.113549.1.1.2";

    /**
     * Object identifier for the MD4 with RSA signature algorithm.
     */
    public static final String OID_MD4_WITH_RSA = "1.2.840.113549.1.1.3";

    /**
     * Object identifier for the MD5 with RSA signature algorithm.
     */
    public static final String OID_MD5_WITH_RSA = "1.2.840.113549.1.1.4";

    /**
     * Object identifier for the SHA1 with RSA signature algorithm.
     */
    public static final String OID_SHA1_WITH_RSA = "1.2.840.113549.1.1.5";

    /**
     * Object identifier for the SHA-256 with RSA signature algorithm.
     */
    public static final String OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";

    /**
     * Object identifier for the SHA-384 with RSA signature algorithm.
     */
    public static final String OID_SHA384_WITH_RSA = "1.2.840.113549.1.1.12";

    /**
     * Object identifier for the SHA-512 with RSA signature algorithm.
     */
    public static final String OID_SHA512_WITH_RSA = "1.2.840.113549.1.1.13";

    /**
     * Object identifier for the PKCS #9 {@code extensionRequest} attribute.
     *
     * @since 1.2.0
     */
    public static final String OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";

    // 1.2.840.113549.2

    /**
     * Object identifier for the MD2 hash algorithm.
     */
    public static final String OID_MD2 = "1.2.840.113549.2.2";

    /**
     * Object identifier for the MD5 hash algorithm.
     */
    public static final String OID_MD5 = "1.2.840.113549.2.5";

    // 1.3.14

    /**
     * Object identifier for the SHA1 hash algorithm.
     */
    public static final String OID_SHA1 = "1.3.14.3.2.26";

    /**
     * Algorithm ID for RSA keys used for any purpose.
     */
    public static final String OID_RSA = "1.2.840.113549.1.1.1";

    /**
     * Algorithm ID for DSA keys used for any purpose.
     */
    public static final String OID_DSA = "1.2.840.10040.4.1";

    /**
     * Algorithm ID for EC keys used for any purpose.
     */
    public static final String OID_EC = "1.2.840.10045.2.1";

    /**
     * Format an AS.1 string from the given decoder as a string.
     *
     * @param decoder the ASN.1 decoder
     * @return the formatted string
     */
    public static String formatAsn1(ASN1Decoder decoder) {
        final StringBuilder builder = new StringBuilder();
        formatAsn1(decoder, builder);
        return builder.toString();
    }

    /**
     * Format an AS.1 string from the given decoder as a string.
     *
     * @param decoder the ASN.1 decoder
     * @param builder the target string builder
     */
    public static void formatAsn1(ASN1Decoder decoder, StringBuilder builder) {
        while (decoder.hasNextElement()) {
            final int type = decoder.peekType();
            switch (type) {
                case INTEGER_TYPE: {
                    builder.append("[int:").append(decoder.decodeInteger()).append("]");
                    break;
                }
                case BIT_STRING_TYPE: {
                    builder.append("[bits:").append(decoder.decodeBitStringAsString()).append(']');
                    break;
                }
                case OCTET_STRING_TYPE: {
                    builder.append("[octets:").append(Arrays2.toString(decoder.decodeOctetString())).append(']');
                    break;
                }
                case NULL_TYPE: {
                    builder.append("[null]");
                    decoder.decodeNull();
                    break;
                }
                case OBJECT_IDENTIFIER_TYPE: {
                    builder.append("[oid:").append(decoder.decodeObjectIdentifier()).append(']');
                    break;
                }
                case IA5_STRING_TYPE: {
                    builder.append("[ia5:").append(decoder.decodeIA5String()).append(']');
                    break;
                }
                case SEQUENCE_TYPE: {
                    builder.append("[sequence:");
                    decoder.startSequence();
                    formatAsn1(decoder, builder);
                    decoder.endSequence();
                    builder.append(']');
                    break;
                }
                case SET_TYPE: {
                    builder.append("[set:");
                    decoder.startSet();
                    formatAsn1(decoder, builder);
                    decoder.endSet();
                    builder.append(']');
                    break;
                }
                case PRINTABLE_STRING_TYPE: {
                    builder.append("[printable:").append(decoder.decodePrintableString()).append(']');
                    break;
                }
                default: {
                    throw log.asnUnknownTagType(type);
//                    builder.append("[unknown(").append(type).append(")]");
//                    decoder.decodeOctetString();
//                    break;
                }
            }
        }
    }

    /**
     * Resolves a key algorithm based on a given <code>oid</code>.
     *
     * @param oid an ASN.1 object identifier or OID (not {@code null})
     * @return the string representing the key algorithm or null if no algorithm could be resolved for the given OID
     */
    public static String keyAlgorithmFromOid(String oid) {
        switch (oid) {
            case OID_RSA:
                return "RSA";
            case OID_DSA:
                return "DSA";
            case OID_EC:
                return "EC";
            default:
                return null;
        }
    }

    @SuppressWarnings("SpellCheckingInspection")
    public static String oidFromSignatureAlgorithm(String algorithmName) {
        switch (algorithmName) {
            case "NONEwithRSA": {
                return null;
            }
            case "MD2withRSA": {
                return OID_MD2_WITH_RSA;
            }
            case "MD5withRSA": {
                return OID_MD5_WITH_RSA;
            }
            case "SHA1withRSA": {
                return OID_SHA1_WITH_RSA;
            }
            case "SHA256withRSA": {
                return OID_SHA256_WITH_RSA;
            }
            case "SHA384withRSA": {
                return OID_SHA384_WITH_RSA;
            }
            case "SHA512withRSA": {
                return OID_SHA512_WITH_RSA;
            }
            case "NONEwithDSA": {
                return null;
            }
            case "SHA1withDSA": {
                return OID_SHA1_WITH_DSA;
            }
            case "SHA256withDSA": {
                return OID_SHA256_WITH_DSA;
            }
            case "NONEwithECDSA": {
                return null;
            }
            case "ECDSA": // obsolete alias for SHA1withECDSA
            case "SHA1withECDSA": {
                return OID_SHA1_WITH_ECDSA;
            }
            case "SHA256withECDSA": {
                return OID_SHA256_WITH_ECDSA;
            }
            case "SHA384withECDSA": {
                return OID_SHA384_WITH_ECDSA;
            }
            case "SHA512withECDSA": {
                return OID_SHA512_WITH_ECDSA;
            }
            default: {
                return null;
            }
        }
    }

    @SuppressWarnings("SpellCheckingInspection")
    public static String signatureAlgorithmFromOid(String oid) {
        switch (oid) {
            case OID_MD2_WITH_RSA: {
                return "MD2withRSA";
            }
            case OID_MD5_WITH_RSA: {
                return "MD5withRSA";
            }
            case OID_SHA1_WITH_RSA: {
                return "SHA1withRSA";
            }
            case OID_SHA256_WITH_RSA: {
                return "SHA256withRSA";
            }
            case OID_SHA384_WITH_RSA: {
                return "SHA384withRSA";
            }
            case OID_SHA512_WITH_RSA: {
                return "SHA512withRSA";
            }
            case OID_SHA1_WITH_DSA: {
                return "SHA1withDSA";
            }
            case OID_SHA1_WITH_ECDSA: {
                return "SHA1withECDSA";
            }
            case OID_SHA256_WITH_ECDSA: {
                return "SHA256withECDSA";
            }
            case OID_SHA384_WITH_ECDSA: {
                return "SHA384withECDSA";
            }
            case OID_SHA512_WITH_ECDSA: {
                return "SHA512withECDSA";
            }
            default: {
                return null;
            }
        }
    }

    public static void validatePrintableByte(final int b) throws ASN1Exception {
        switch (b) {
            case ' ':
            case '\'':
            case '(':
            case ')':
            case '+':
            case ',':
            case '-':
            case '.':
            case '/':
            case ':':
            case '=':
            case '?': {
                return;
            }
            default: {
                if ('A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9') {
                    return;
                }
                throw log.asnUnexpectedCharacterByteForPrintableString();
            }
        }
    }
}
