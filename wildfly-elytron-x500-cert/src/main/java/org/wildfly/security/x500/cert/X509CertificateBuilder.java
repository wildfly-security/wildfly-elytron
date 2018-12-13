/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.util.ASN1;
import org.wildfly.security.asn1.DEREncoder;

/**
 * A builder for X.509 certificates.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X509CertificateBuilder {

    private static final ZonedDateTime LATEST_VALID = ZonedDateTime.of(9999, 12, 31, 23, 59, 59, 0, ZoneOffset.UTC);

    private int version = 3;
    private BigInteger serialNumber = BigInteger.ONE;
    private X500Principal subjectDn;
    private byte[] subjectUniqueId;
    private X500Principal issuerDn;
    private byte[] issuerUniqueId;
    private ZonedDateTime notValidBefore = ZonedDateTime.now();
    private ZonedDateTime notValidAfter = LATEST_VALID;
    private final Map<String, X509CertificateExtension> extensionsByOid = new LinkedHashMap<>();
    private PublicKey publicKey;
    private PrivateKey signingKey;
    private String signatureAlgorithmName;

    /**
     * Construct a new uninitialized instance.
     */
    public X509CertificateBuilder() {
    }

    /**
     * Add a certificate extension.  If an extension with the same OID already exists, an exception is thrown.
     *
     * @param extension the extension to add (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder addExtension(X509CertificateExtension extension) {
        Assert.checkNotNullParam("extension", extension);
        final String oid = extension.getId();
        Assert.checkNotNullParam("extension.getOid()", oid);
        if (extensionsByOid.putIfAbsent(oid, extension) != null) {
            throw log.extensionAlreadyExists(oid);
        }
        return this;
    }

    /**
     * Add or replace a certificate extension.  If an extension with the same OID already exists, it is replaced
     * and returned.
     *
     * @param extension the extension to add (must not be {@code null})
     * @return the existing extension, or {@code null} if no other extension with the same OID was existent
     */
    public X509CertificateExtension addOrReplaceExtension(X509CertificateExtension extension) {
        Assert.checkNotNullParam("extension", extension);
        final String oid = extension.getId();
        Assert.checkNotNullParam("extension.getOid()", oid);
        return extensionsByOid.put(oid, extension);
    }

    /**
     * Remove the extension with the given OID, if it is registered.
     *
     * @param oid the OID of the extension to remove
     * @return the extension, or {@code null} if no extension with the same OID was existent
     */
    public X509CertificateExtension removeExtension(String oid) {
        Assert.checkNotNullParam("oid", oid);
        return extensionsByOid.remove(oid);
    }

    /**
     * Get the certificate version.
     *
     * @return the certificate version
     */
    public int getVersion() {
        return version;
    }

    /**
     * Set the certificate version.
     *
     * @param version the certificate version (must be between 1 and 3, inclusive)
     * @return this builder instance
     */
    public X509CertificateBuilder setVersion(final int version) {
        Assert.checkMinimumParameter("version", 1, version);
        Assert.checkMaximumParameter("version", 3, version);
        this.version = version;
        return this;
    }

    /**
     * Get the serial number of the certificate being built.
     *
     * @return the serial number of the certificate being built (must not be {@code null})
     */
    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    /**
     * Set the serial number of the certificate being built.  The serial number must be positive and no larger
     * than 20 octets (or 2^160).
     *
     * @param serialNumber the serial number of the certificate being built
     * @return this builder instance
     */
    public X509CertificateBuilder setSerialNumber(final BigInteger serialNumber) {
        Assert.checkNotNullParam("serialNumber", serialNumber);
        if (BigInteger.ONE.compareTo(serialNumber) > 0) {
            throw log.serialNumberTooSmall();
        }
        if (serialNumber.bitLength() > 20*8) {
            throw log.serialNumberTooLarge();
        }
        this.serialNumber = serialNumber;
        return this;
    }

    /**
     * Get the subject DN.
     *
     * @return the subject DN
     */
    public X500Principal getSubjectDn() {
        return subjectDn;
    }

    /**
     * Set the subject DN.
     *
     * @param subjectDn the subject DN (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setSubjectDn(final X500Principal subjectDn) {
        Assert.checkNotNullParam("subjectDn", subjectDn);
        this.subjectDn = subjectDn;
        return this;
    }

    /**
     * Get the subject unique ID.
     *
     * @return the subject unique ID
     */
    public byte[] getSubjectUniqueId() {
        return subjectUniqueId;
    }

    /**
     * Set the subject unique ID.
     *
     * @param subjectUniqueId the subject unique ID (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setSubjectUniqueId(final byte[] subjectUniqueId) {
        Assert.checkNotNullParam("subjectUniqueId", subjectUniqueId);
        this.subjectUniqueId = subjectUniqueId;
        return this;
    }

    /**
     * Get the issuer DN.
     *
     * @return the issuer DN
     */
    public X500Principal getIssuerDn() {
        return issuerDn;
    }

    /**
     * Set the issuer DN.
     *
     * @param issuerDn the issuer DN (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setIssuerDn(final X500Principal issuerDn) {
        Assert.checkNotNullParam("issuerDn", issuerDn);
        this.issuerDn = issuerDn;
        return this;
    }

    /**
     * Get the issuer unique ID.
     *
     * @return the issuer unique ID
     */
    public byte[] getIssuerUniqueId() {
        return issuerUniqueId;
    }

    /**
     * Set the issuer unique ID.
     *
     * @param issuerUniqueId the issuer unique ID (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setIssuerUniqueId(final byte[] issuerUniqueId) {
        Assert.checkNotNullParam("issuerUniqueId", issuerUniqueId);
        this.issuerUniqueId = issuerUniqueId;
        return this;
    }

    /**
     * Get the not-valid-before date.  The default is the date when this builder was constructed.
     *
     * @return the not-valid-before date
     */
    public ZonedDateTime getNotValidBefore() {
        return notValidBefore;
    }

    /**
     * Set the not-valid-before date.
     *
     * @param notValidBefore the not-valid-before date (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setNotValidBefore(final ZonedDateTime notValidBefore) {
        Assert.checkNotNullParam("notValidBefore", notValidBefore);
        this.notValidBefore = notValidBefore;
        return this;
    }

    /**
     * Get the not-valid-after date.  The default is equal to {@code 99991231235959Z} as specified in {@code RFC 5280}.
     *
     * @return the not-valid-after date
     */
    public ZonedDateTime getNotValidAfter() {
        return notValidAfter;
    }

    /**
     * Set the not-valid-after date.
     *
     * @param notValidAfter the not-valid-after date (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setNotValidAfter(final ZonedDateTime notValidAfter) {
        Assert.checkNotNullParam("notValidAfter", notValidAfter);
        this.notValidAfter = notValidAfter;
        return this;
    }

    /**
     * Get the public key.
     *
     * @return the public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Set the public key.
     *
     * @param publicKey the public key (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setPublicKey(final PublicKey publicKey) {
        Assert.checkNotNullParam("publicKey", publicKey);
        this.publicKey = publicKey;
        return this;
    }

    /**
     * Get the signing key.
     *
     * @return the signing key
     */
    public PrivateKey getSigningKey() {
        return signingKey;
    }

    /**
     * Set the signing key.
     *
     * @param signingKey the signing key (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setSigningKey(final PrivateKey signingKey) {
        Assert.checkNotNullParam("signingKey", signingKey);
        this.signingKey = signingKey;
        return this;
    }

    /**
     * Get the signature algorithm name.
     *
     * @return the signature algorithm name
     */
    public String getSignatureAlgorithmName() {
        return signatureAlgorithmName;
    }

    /**
     * Set the signature algorithm name.
     *
     * @param signatureAlgorithmName the signature algorithm name (must not be {@code null})
     * @return this builder instance
     */
    public X509CertificateBuilder setSignatureAlgorithmName(final String signatureAlgorithmName) {
        Assert.checkNotNullParam("signatureAlgorithmName", signatureAlgorithmName);
        this.signatureAlgorithmName = signatureAlgorithmName;
        return this;
    }

    /**
     * Attempt to construct and sign an X.509 certificate according to the information in this builder.
     *
     * @return the constructed certificate
     * @throws IllegalArgumentException if one or more of the builder parameters are invalid or missing
     * @throws CertificateException if the certificate failed to be constructed
     */
    public X509Certificate build() throws CertificateException {
        byte[] tbsCertificate = getTBSBytes();

        DEREncoder derEncoder = new DEREncoder();
        derEncoder.startSequence(); // Certificate
        derEncoder.writeEncoded(tbsCertificate);

        // signatureAlgorithm
        final String signatureAlgorithmName = this.signatureAlgorithmName;
        final String signatureAlgorithmOid = ASN1.oidFromSignatureAlgorithm(signatureAlgorithmName);
        if (signatureAlgorithmOid == null) {
            throw log.asnUnrecognisedAlgorithm(signatureAlgorithmName);
        }

        derEncoder.startSequence(); // AlgorithmIdentifier
        derEncoder.encodeObjectIdentifier(signatureAlgorithmOid);
        derEncoder.endSequence(); // AlgorithmIdentifier
        try {
            final Signature signature = Signature.getInstance(signatureAlgorithmName);
            signature.initSign(signingKey);
            signature.update(tbsCertificate);
            derEncoder.encodeBitString(signature.sign());
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw log.certSigningFailed(e);
        }
        derEncoder.endSequence(); // Certificate

        byte[] bytes = derEncoder.getEncoded();
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(bytes));
    }

    byte[] getTBSBytes() {
        final BigInteger serialNumber = this.serialNumber;
        // Cache and/or validate all fields.
        final int version = this.version;
        final String signatureAlgorithmName = this.signatureAlgorithmName;
        if (signatureAlgorithmName == null) {
            throw log.noSignatureAlgorithmNameGiven();
        }
        final String signatureAlgorithmOid = ASN1.oidFromSignatureAlgorithm(signatureAlgorithmName);
        if (signatureAlgorithmOid == null) {
            throw log.unknownSignatureAlgorithmName(signatureAlgorithmName);
        }
        final PrivateKey signingKey = this.signingKey;
        if (signingKey == null) {
            throw log.noSigningKeyGiven();
        }
        String signingKeyAlgorithm = signingKey.getAlgorithm();
        if (signingKeyAlgorithm.equals("EC")) {
            signingKeyAlgorithm = "ECDSA";
        }
        if (! signatureAlgorithmName.endsWith("with" + signingKeyAlgorithm) || signatureAlgorithmName.contains("with" + signingKeyAlgorithm + "and")) {
            throw log.signingKeyNotCompatWithSig(signingKey.getAlgorithm(), signatureAlgorithmName);
        }
        final ZonedDateTime notValidBefore = this.notValidBefore;
        final ZonedDateTime notValidAfter = this.notValidAfter;
        if (notValidBefore.compareTo(notValidAfter) > 0) {
            throw log.validAfterBeforeValidBefore(notValidBefore, notValidAfter);
        }
        final X500Principal issuerDn = this.issuerDn;
        if (issuerDn == null) {
            throw log.noIssuerDnGiven();
        }
        final X500Principal subjectDn = this.subjectDn;
        final PublicKey publicKey = this.publicKey;
        if (publicKey == null) {
            throw log.noPublicKeyGiven();
        }
        final byte[] issuerUniqueId = this.issuerUniqueId;
        final byte[] subjectUniqueId = this.subjectUniqueId;
        if (version < 2 && (issuerUniqueId != null || subjectUniqueId != null)) {
            throw log.uniqueIdNotAllowed();
        }
        final Map<String, X509CertificateExtension> extensionsByOid = this.extensionsByOid;
        if (version < 3 && ! extensionsByOid.isEmpty()) {
            throw log.extensionsNotAllowed();
        }

        DEREncoder derEncoder = new DEREncoder();

        derEncoder.startSequence(); // TBSCertificate

        derEncoder.startExplicit(0);
        derEncoder.encodeInteger(version - 1);
        derEncoder.endExplicit();
        derEncoder.encodeInteger(serialNumber);
        derEncoder.startSequence(); // AlgorithmIdentifier
        derEncoder.encodeObjectIdentifier(signatureAlgorithmOid);
        derEncoder.endSequence(); // AlgorithmIdentifier
        derEncoder.writeEncoded(issuerDn.getEncoded()); // already a SEQUENCE of SET of SEQUENCE of { OBJECT IDENTIFIER, ANY }
        derEncoder.startSequence(); // Validity
        derEncoder.encodeGeneralizedTime(notValidBefore.withZoneSameInstant(ZoneOffset.UTC));
        derEncoder.encodeGeneralizedTime(notValidAfter.withZoneSameInstant(ZoneOffset.UTC));
        derEncoder.endSequence(); // Validity
        if (subjectDn != null) derEncoder.writeEncoded(subjectDn.getEncoded()); // already a SEQUENCE of SET of SEQUENCE of { OBJECT IDENTIFIER, ANY }

        final X509EncodedKeySpec keySpec;
        final String publicKeyAlgorithm = publicKey.getAlgorithm();
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(publicKeyAlgorithm);
            final Key translatedKey = keyFactory.translateKey(publicKey);
            keySpec = keyFactory.getKeySpec(translatedKey, X509EncodedKeySpec.class);
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            throw log.invalidKeyForCert(publicKeyAlgorithm, e);
        }
        derEncoder.writeEncoded(keySpec.getEncoded()); // SubjectPublicKeyInfo

        if (issuerUniqueId != null) {
            derEncoder.encodeImplicit(1);
            derEncoder.encodeBitString(issuerUniqueId);
        }
        if (subjectUniqueId != null) {
            derEncoder.encodeImplicit(2);
            derEncoder.encodeBitString(subjectUniqueId);
        }
        if (! extensionsByOid.isEmpty()) {
            derEncoder.startExplicit(3);
            derEncoder.startSequence();
            for (X509CertificateExtension extension : extensionsByOid.values()) {
                derEncoder.startSequence();
                derEncoder.encodeObjectIdentifier(extension.getId());
                if (extension.isCritical()) derEncoder.encodeBoolean(true);
                final DEREncoder subEncoder = new DEREncoder();
                extension.encodeTo(subEncoder);
                derEncoder.encodeOctetString(subEncoder.getEncoded());
                derEncoder.endSequence();
            }
            derEncoder.endSequence();
            derEncoder.endExplicit();
        }

        derEncoder.endSequence(); // TBSCertificate

        return derEncoder.getEncoded();
    }
}
