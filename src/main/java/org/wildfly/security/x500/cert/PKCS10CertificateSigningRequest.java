/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.x500.cert;

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.util.ByteStringBuilder;


/**
 * A PKCS #10 certificate signing request defined in <a href="https://tools.ietf.org/html/rfc2986">RFC 2986</a> as:
 *
 * <pre>
 *      CertificationRequest ::= SEQUENCE {
 *          certificationRequestInfo    CertificationRequestInfo,
 *          signatureAlgorithm          AlgorithmIdentifier{{ SignatureAlgorithms }},
 *          signature                   BIT STRING
 *      }
 *
 *      CertificationRequestInfo ::= SEQUENCE {
 *          version         INTEGER { v1(0) } (v1,...),
 *          subject         Name,
 *          subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *          attributes      [0] Attributes{{ CRIAttributes }}
 *      }
 *
 *      Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 *
 *      Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *          type        ATTRIBUTE.&id({IOSet}),
 *          values      SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{\@type})
 *      }
 *
 *      AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
 *          algorithm       ALGORITHM.&id({IOSet}),
 *          parameters      ALGORITHM.&Type({IOSet}{{@literal @}algorithm}) OPTIONAL
 *      }
 * </pre>
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.2.0
 */
public final class PKCS10CertificateSigningRequest {

    private final PublicKey publicKey;
    private final X500Principal subjectDn;
    private final List<X509CertificateExtension> extensions;
    private final byte[] encoded;

    private PKCS10CertificateSigningRequest(Builder builder, final byte[] encoded) {
        this.publicKey = builder.publicKey;
        this.subjectDn = builder.subjectDn;
        this.extensions = new ArrayList<>(builder.extensionsByOid.values());
        this.encoded = encoded;
    }

    /**
     * Get this PKCS #10 certificate signing request in binary format.
     *
     * @return this PKCS #10 certificate signing request in binary format
     */
    public byte[] getEncoded() {
        return encoded.clone();
    }

    /**
     * Get this PKCS #10 certificate signing request in PEM format.
     *
     * @return this PKCS #10 certificate signing request in PEM format
     */
    public ByteStringBuilder getPem() {
        ByteStringBuilder pem = new ByteStringBuilder();
        Pem.generatePemPKCS10CertificateSigningRequest(pem, this);
        return pem;
    }

    /**
     * Get the public key associated with this PKCS #10 certificate signing request.
     *
     * @return the public key associated with this PKCS #10 certificate signing request
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Get the subject DN associated with this PKCS #10 certificate signing request.
     *
     * @return the subject DN associated with this PKCS #10 certificate signing request
     */
    public X500Principal getSubjectDn() {
        return subjectDn;
    }

    /**
     * Get the X.509 certificate extensions included in this PKCS #10 certificate signing request.
     *
     * @return the X.509 certificate extensions included in this PKCS #10 certificate signing request
     */
    public List<X509CertificateExtension> getExtensions() {
        return extensions;
    }

    /**
     * Construct a new builder instance.
     *
     * @return the new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A {@code Builder} to configure and generate a {@code PKCS10CertificateSigningRequest}.
     */
    public static class Builder {

        private static final int VERSION = 0; // PKCS #10 version

        private Certificate certificate;
        private PublicKey publicKey;
        private PrivateKey signingKey;
        private String signatureAlgorithmName;
        private String signatureAlgorithmOid;
        private X500Principal subjectDn;
        private final Map<String, X509CertificateExtension> extensionsByOid = new LinkedHashMap<>();

        /**
         * Construct a new uninitialized instance.
         */
        Builder() {
        }

        /**
         * Set the certificate.
         *
         * @param certificate the certificate (must not be {@code null})
         * @return this builder instance
         */
        public Builder setCertificate(final Certificate certificate) {
            Assert.checkNotNullParam("certificate", certificate);
            this.certificate = certificate;
            this.publicKey = certificate.getPublicKey();
            return this;
        }

        /**
         * Set the signing key.
         *
         * @param signingKey the signing key (must not be {@code null})
         * @return this builder instance
         */
        public Builder setSigningKey(final PrivateKey signingKey) {
            Assert.checkNotNullParam("signingKey", signingKey);
            this.signingKey = signingKey;
            return this;
        }

        /**
         * Set the subject DN.
         *
         * @param subjectDn the subject DN (must not be {@code null})
         * @return this builder instance
         */
        public Builder setSubjectDn(final X500Principal subjectDn) {
            Assert.checkNotNullParam("subjectDn", subjectDn);
            this.subjectDn = subjectDn;
            return this;
        }

        /**
         * Set the signature algorithm name.
         *
         * @param signatureAlgorithmName the signature algorithm name (must not be {@code null})
         * @return this builder instance
         */
        public Builder setSignatureAlgorithmName(final String signatureAlgorithmName) {
            Assert.checkNotNullParam("signatureAlgorithmName", signatureAlgorithmName);
            this.signatureAlgorithmName = signatureAlgorithmName;
            return this;
        }

        /**
         * Add an X.509 certificate extension that should be included in the certificate signing request.
         * If an extension with the same OID already exists, an exception is thrown.
         *
         * @param extension the extension to add (must not be {@code null})
         * @return this builder instance
         * @throws IllegalArgumentException if an extension with the same OID has already been added
         */
        public Builder addExtension(X509CertificateExtension extension) throws IllegalArgumentException {
            Assert.checkNotNullParam("extension", extension);
            final String oid = extension.getId();
            Assert.checkNotNullParam("extension.getOid()", oid);
            if (extensionsByOid.putIfAbsent(oid, extension) != null) {
                throw log.extensionAlreadyExists(oid);
            }
            return this;
        }

        /**
         * Attempt to generate a PKCS #10 certificate signing request.
         *
         * @return the PKCS #10 certificate signing request
         * @throws IllegalArgumentException if a required builder parameter is missing or invalid
         */
        public PKCS10CertificateSigningRequest build() throws IllegalArgumentException {
            if (certificate == null) {
                throw log.noCertificateGiven();
            }
            if (signingKey == null) {
                throw log.noSigningKeyGiven();
            }
            if (signatureAlgorithmName == null) {
                signatureAlgorithmName = getDefaultCompatibleSignatureAlgorithmName(signingKey);
                if (signatureAlgorithmName == null) {
                    throw log.noSignatureAlgorithmNameGiven();
                }
            }
            signatureAlgorithmOid = ASN1.oidFromSignatureAlgorithm(signatureAlgorithmName);
            if (signatureAlgorithmOid == null) {
                throw log.asnUnrecognisedAlgorithm(signatureAlgorithmName);
            }
            final String signingKeyAlgorithm = signingKey.getAlgorithm();
            if (! signatureAlgorithmName.endsWith("with" + signingKeyAlgorithm) || signatureAlgorithmName.contains("with" + signingKeyAlgorithm + "and")) {
                throw log.signingKeyNotCompatWithSig(signingKeyAlgorithm, signatureAlgorithmName);
            }
            if (subjectDn == null) {
                subjectDn = ((X509Certificate) certificate).getSubjectX500Principal();
            }

            // add the Subject Key Identifier Extension if it's not already present
            final X509CertificateExtension subjectKeyIdentifierExtension = new SubjectKeyIdentifierExtension(getKeyIdentifier(publicKey));
            addExtension(subjectKeyIdentifierExtension);

            ByteStringBuilder certificationRequest = new ByteStringBuilder();
            DEREncoder encoder = new DEREncoder(certificationRequest);
            encodeCertificationRequest(encoder);
            return new PKCS10CertificateSigningRequest(this, certificationRequest.toArray());
        }

        /**
         * Encode a {@code CertificationRequest} using the given DER encoder. The ASN.1 definition of {@code CertificationRequest} is:
         *
         * <pre>
         *      CertificationRequest ::= SEQUENCE {
         *          certificationRequestInfo    CertificationRequestInfo,
         *          signatureAlgorithm          AlgorithmIdentifier{{ SignatureAlgorithms }},
         *          signature                   BIT STRING
         *      }
         * </pre>
         *
         * @param encoder the DER encoder
         */
        private void encodeCertificationRequest(final DEREncoder encoder) {
            ByteStringBuilder tbsCertificationRequestInfo = new ByteStringBuilder();
            DEREncoder tbsEncoder = new DEREncoder(tbsCertificationRequestInfo);
            encodeCertificationRequestInfo(tbsEncoder);

            byte[] signatureBytes;
            try {
                final Signature signature = Signature.getInstance(signatureAlgorithmName);
                signature.initSign(signingKey);
                signature.update(tbsCertificationRequestInfo.toArray());
                signatureBytes = signature.sign();
            } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
                throw log.certRequestInfoSigningFailed(e);
            }

            // CertificationRequest
            encoder.startSequence();
            encoder.writeEncoded(tbsCertificationRequestInfo.toArray());
            encodeAlgorithmIdentifier(encoder);
            encoder.encodeBitString(signatureBytes);
            encoder.endSequence();
        }

        /**
         * Encode a {@code CertificationRequestInfo} using the given DER encoder. The ASN.1 definition of {@code CertificationRequestInfo} is:
         *
         * <pre>
         *      CertificationRequestInfo ::= SEQUENCE {
         *          version         INTEGER { v1(0) } (v1,...),
         *          subject         Name,
         *          subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
         *          attributes      [0] Attributes{{ CRIAttributes }}
         *      }
         * </pre>
         *
         * @param encoder the DER encoder
         */
        private void encodeCertificationRequestInfo(final DEREncoder encoder) {
            encoder.startSequence();
            encoder.encodeInteger(VERSION);
            encoder.writeEncoded(subjectDn.getEncoded());
            encoder.writeEncoded(publicKey.getEncoded()); // subjectPKInfo
            encoder.encodeImplicit(0);
            encodeAttributes(encoder);
            encoder.endSequence();
        }

        /**
         * Encode an {@code AlgorithmIdentifier} using the given DER encoder. The ASN.1 definition of {@code AlgorithmIdentifier} is:
         *
         * <pre>
         *      AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
         *          algorithm       ALGORITHM.&id({IOSet}),
         *          parameters      ALGORITHM.&Type({IOSet}{{@literal @}algorithm}) OPTIONAL
         *      }
         * </pre>
         *
         * @param encoder the DER encoder
         */
        private void encodeAlgorithmIdentifier(final DEREncoder encoder) {
            encoder.startSequence();
            encoder.encodeObjectIdentifier(signatureAlgorithmOid);
            if (signingKey.getAlgorithm().equals("RSA")) {
                // Include the NULL parameter for RSA based signature algorithms only, as per RFC 3279 (http://www.ietf.org/rfc/rfc3279)
                encoder.encodeNull();
            }
            encoder.endSequence();
        }

        /**
         * Encode {@code Attributes} using the given DER encoder. The ASN.1 definition of {@code Attributes} is:
         *
         * <pre>
         *      Attributes ::= SET OF Attribute
         *
         *      Attribute :: SEQUENCE {
         *          type    AttributeType,
         *          values  SET OF AttributeValue
         *      }
         *
         *      AttributeType  ::= OBJECT IDENTIFIER
         *      AttributeValue ::= ANY defined by type
         * </pre>
         *
         * @param encoder the DER encoder
         */
        private void encodeAttributes(final DEREncoder encoder) {
            encoder.startSetOf();
            encoder.startSequence(); // extensionRequest attribute
            encoder.encodeObjectIdentifier(ASN1.OID_EXTENSION_REQUEST);
            encoder.startSetOf();
            encodeExtensionRequest(encoder);
            encoder.endSetOf();
            encoder.endSequence();
            encoder.endSetOf();
        }

        /**
         * Encode an {@code ExtensionRequest} using the given DER encoder. The ASN.1 definition of {@code ExtensionRequest} is:
         *
         * <pre>
         *     ExtensionRequest ::= Extensions
         *     Extensions ::= SEQUENCE OF Extension
         * </pre>
         *
         * @param encoder the DER encoder
         */
        private void encodeExtensionRequest(final DEREncoder encoder) {
            encoder.startSequence();
            for (X509CertificateExtension extension : extensionsByOid.values()) {
                encodeExtension(encoder, extension);
            }
            encoder.endSequence();
        }

        /**
         * Encode an {@code Extension} using the given DER encoder. The ASN.1 definition of {@code Extension} is:
         *
         * <pre>
         *      Extension ::= SEQUENCE {
         *          extensionId     OBJECT IDENTIFIER,
         *          critical        BOOLEAN DEFAULT FALSE,
         *          extensionValue  OCTET STRING
         *      }
         * </pre>
         *
         * @param encoder the DER encoder
         * @param extension the X.509 certificate extension
         */
        private static void encodeExtension(final DEREncoder encoder, final X509CertificateExtension extension) {
            encoder.startSequence();
            encoder.encodeObjectIdentifier(extension.getId());
            if (extension.isCritical()) {
                encoder.encodeBoolean(true);
            }
            ByteStringBuilder sub = new ByteStringBuilder();
            DEREncoder extensionEncoder = new DEREncoder(sub);
            extension.encodeTo(extensionEncoder);
            encoder.encodeOctetString(sub);
            encoder.endSequence();
        }

        /**
         * Get the key identifier, which is composed of the 160-bit SHA-1 hash of the value of the BIT STRING
         * {@code subjectPublicKey} (excluding the tag, length, and number of unused bits), as per
         * <a href="https://tools.ietf.org/html/rfc3280">RFC 3280</a>.
         *
         * @param publicKey the public key
         * @return the key identifier
         */
        private static byte[] getKeyIdentifier(final PublicKey publicKey) {
            DERDecoder decoder = new DERDecoder(publicKey.getEncoded());
            decoder.startSequence();
            decoder.skipElement(); // skip the algorithm
            byte[] subjectPublicKey = decoder.decodeBitString();
            decoder.endSequence();

            final MessageDigest messageDigest;
            try {
                messageDigest = MessageDigest.getInstance("SHA-1");
                messageDigest.update(subjectPublicKey);
                return messageDigest.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        private static String getDefaultCompatibleSignatureAlgorithmName(final PrivateKey signingKey) {
            final String signingKeyAlgorithm = signingKey.getAlgorithm();
            switch (signingKeyAlgorithm) {
                case "DSA": {
                    return "SHA1withDSA";
                }
                case "RSA": {
                    return "SHA256withRSA";
                }
                case "EC": {
                    return "SHA256withECDSA";
                }
                default: {
                    return null;
                }
            }
        }
    }
}
