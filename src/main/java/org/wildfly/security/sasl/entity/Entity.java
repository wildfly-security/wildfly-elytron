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

package org.wildfly.security.sasl.entity;

import static org.wildfly.security.asn1.util.ASN1.*;

/**
 * Constants for the ISO/IEC 9798-3 authentication SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class Entity {

    // Signature algorithms
    public static final String SHA1_WITH_RSA = "SHA1withRSA";
    public static final String SHA1_WITH_DSA = "SHA1withDSA";
    public static final String SHA1_WITH_ECDSA = "SHA1withECDSA";

    /**
     * Get the object identifier for the given signature algorithm.
     *
     * @param signatureAlgorithm the signature algorithm name
     * @return the object identifier that corresponds to the given algorithm or
     * {@code null} if the given algorithm name is invalid
     */
    public static String algorithmOid(String signatureAlgorithm) {
        switch (signatureAlgorithm) {
            case SHA1_WITH_RSA: return OID_SHA1_WITH_RSA;
            case SHA1_WITH_DSA: return OID_SHA1_WITH_DSA;
            case SHA1_WITH_ECDSA: return OID_SHA1_WITH_ECDSA;
            default: return null;
        }
    }

    /**
     * Get the key type for the given signature algorithm.
     *
     * @param signatureAlgorithm the signature algorithm name
     * @return the key type that corresponds to the given algorithm or {@code null}
     * if the given algorithm name is invalid
     */
    public static String keyType(String signatureAlgorithm) {
        switch (signatureAlgorithm) {
            case SHA1_WITH_RSA: return "RSA";
            case SHA1_WITH_DSA: return "DSA";
            case SHA1_WITH_ECDSA: return "EC_EC";
            default: return null;
        }
    }

}
