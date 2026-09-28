/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.evidence;

/**
 * A piece of evidence that consists of a security token
 * signed with an Elliptic Curve Digital Signature Algorithm (ECDSA).
 */
public class EllipticCurveTokenEvidence extends CommonTokenEvidence {
    private String algorithm;

    public EllipticCurveTokenEvidence(String token) {
        super(token);
    }

    public EllipticCurveTokenEvidence(String token, String algorithm) {
        this(token);
        if (algorithm != null) {
            this.algorithm = algorithmLookup(algorithm.toUpperCase());
        }
    }


    /**
     * Returns the digital signature algorithm associated with
     * the designator for the cryptographic hash function.
     *
     * Table for elliptic curves
     *         "secp256r1" >> ES256 >> "SHA256withECDSA"  SHA-256
     *         "secp384r1" >> ES384 >> "SHA384withECDSA"  SHA-384
     *         "secp521r1" >> ES521 >> "SHA512withECDSA"  SHA-512
     *
     * @param hashDesignator  designator for the cryptographic hash function
     * @return the corresponding digital signature algorithm; null when none found
     */
    @Override
    public String algorithmLookup (String hashDesignator) {
        switch (hashDesignator) {
            case "ES256":
            case "ECDSA-SHA256":
                return "SHA256withECDSA";
            case "ES384":
            case "ECDSA-SHA384":
                return "SHA384withECDSA";
            case "ES512":
            case "ECDSA-SHA12":
                return "SHA512withECDSA";
            default:
                return null;
        }
    }
}