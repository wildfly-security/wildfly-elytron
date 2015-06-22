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

package org.wildfly.security.sasl.util;

import org.wildfly.security.asn1.ASN1;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class TLSServerEndPointChannelBinding {
    private TLSServerEndPointChannelBinding() {}

    static String getDigestAlgorithm(final String sigAlgOID) {
        switch (sigAlgOID) {
            case ASN1.OID_MD2:
            case ASN1.OID_MD2_WITH_RSA:
            case ASN1.OID_MD4_WITH_RSA:
            case ASN1.OID_MD5:
            case ASN1.OID_MD5_WITH_RSA:
            case ASN1.OID_SHA1_WITH_DSA:
            case ASN1.OID_SHA1_WITH_RSA:
            case ASN1.OID_SHA1_WITH_ECDSA:
            case ASN1.OID_SHA1:
            case ASN1.OID_SHA224_WITH_ECDSA:
            case ASN1.OID_SHA256_WITH_RSA:
            case ASN1.OID_SHA256_WITH_ECDSA:
                return "SHA-256";
            case ASN1.OID_SHA384_WITH_ECDSA:
            case ASN1.OID_SHA384_WITH_RSA:
                return "SHA-384";
            case ASN1.OID_SHA512_WITH_ECDSA:
            case ASN1.OID_SHA512_WITH_RSA:
                return "SHA-512";
            default: {
                return null;
            }
        }
    }
}
