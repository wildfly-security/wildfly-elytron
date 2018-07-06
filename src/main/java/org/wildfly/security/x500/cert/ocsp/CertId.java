/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.ocsp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.wildfly.common.Assert;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.asn1.ASN1Decoder;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.util.ASN1;

/**
 * OCSP specific identification of the checked certificate
 */
final class CertId {

    private final String hashAlgorithm;
    private final byte[] issuerNameHash;
    private final byte[] issuerKeyHash;
    private final BigInteger serialNumber;

    /**
     * Construct an OCSP specific certificate identifier.
     * @param hashAlgorithm the ASN.1 OID of hash algorithm used to hash following params
     * @param issuerNameHash the hash of issuer's DN
     * @param issuerKeyHash the hash of issuer's public key
     * @param serialNumber the serial number of the certificate to check
     */
    CertId(String hashAlgorithm, byte[] issuerNameHash, byte[] issuerKeyHash, BigInteger serialNumber) {
        this.hashAlgorithm = hashAlgorithm;
        this.issuerNameHash = issuerNameHash;
        this.issuerKeyHash = issuerKeyHash;
        this.serialNumber = serialNumber;
    }

    /**
     * Build the certificate identifier from the certificate and its issuer's certificate
     * @param certificate the certificate to check
     * @param issuer the issuers certificate (direct parent of the certificate)
     * @return the certificate identifier
     */
    static CertId fromCertificate(X509Certificate certificate, X509Certificate issuer) {
        Assert.checkNotNullParam("certificate", certificate);
        Assert.checkNotNullParam("issuer", issuer);
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //        algorithm            AlgorithmIdentifier,
        //        subjectPublicKey     BIT STRING
        // }
        ASN1Decoder decoder = new DERDecoder(issuer.getPublicKey().getEncoded());
        decoder.startSequence();
        decoder.skipElement(); // AlgorithmIdentifier
        byte[] subjectPublicKey = decoder.decodeBitString();
        decoder.endSequence();

        return new CertId(
                ASN1.OID_SHA1,
                digest.digest(issuer.getSubjectX500Principal().getEncoded()),
                digest.digest(subjectPublicKey),
                certificate.getSerialNumber()
        );
    }

    /**
     * Get the ASN.1 OID of hash algorithm used to hash following params.
     * @return the ASN.1 OID of hash algorithm used to hash following params
     */
    String getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Get the hash of issuer's DN.
     * @return the hash of issuer's DN
     */
    byte[] getIssuerNameHash() {
        return issuerNameHash;
    }

    /**
     * Get the hash of issuer's public key.
     * @return the hash of issuer's public key
     */
    byte[] getIssuerKeyHash() {
        return issuerKeyHash;
    }

    /**
     * Get the serial number of the certificate to check.
     * @return the serial number of the certificate to check
     */
    BigInteger getSerialNumber() {
        return serialNumber;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (! (o instanceof CertId)) return false;
        CertId c = (CertId) o;
        return hashAlgorithm.equals(c.hashAlgorithm) &&
                Arrays.equals(issuerNameHash, c.issuerNameHash) &&
                Arrays.equals(issuerKeyHash, c.issuerKeyHash) &&
                serialNumber.equals(c.serialNumber);
    }

    @Override
    public int hashCode() {
        int result = hashAlgorithm.hashCode();
        result = 31 * result + Arrays.hashCode(issuerNameHash);
        result = 31 * result + Arrays.hashCode(issuerKeyHash);
        result = 31 * result + serialNumber.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "CertId{hashAlgorithm='" + hashAlgorithm +
                "', issuerNameHash=" + ByteIterator.ofBytes(issuerNameHash).hexEncode().drainToString() +
                ", issuerKeyHash=" + ByteIterator.ofBytes(issuerKeyHash).hexEncode().drainToString() +
                ", serialNumber=" + serialNumber + '}';
    }
}
