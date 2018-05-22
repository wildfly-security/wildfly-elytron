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
import static org.wildfly.security.x500.cert.CertUtil.getDefaultCompatibleSignatureAlgorithmName;
import static org.wildfly.security.x500.cert.CertUtil.getKeyIdentifier;
import static org.wildfly.security.x500.cert.CertUtil.getX509CertificateExtension;

import java.security.InvalidKeyException;
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
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.asn1.util.ASN1;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.pem.Pem;


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
    public byte[] getPem() {
        ByteStringBuilder pem = new ByteStringBuilder();
        Pem.generatePemPKCS10CertificateSigningRequest(pem, this);
        return pem.toArray();
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
         * Add an X.509 certificate extension that should be included in the certificate signing request using
         * the given extension name and string value. If an extension with the same name already exists, an exception is thrown.
         * The following extension names and values are supported:
         *
         * <ul>
         *   <li> {@code name: BasicConstraints} <br/>
         *        {@code value: ca:{true|false}[,pathlen:<len>]} where {@code ca} indicates whether or not the subject
         *        is a CA. If {@code ca} is true, {@code pathlen} indicates the path length constraint.
         *   </li>
         *   <br/>
         *   <li> {@code name: KeyUsage} <br/>
         *        {@code value: usage(,usage)*} where {@code value} is a list of the allowed key usages, where each
         *        {@code usage} value must be one of the following ({@code usage} values are case-sensitive):
         *        <ul>
         *            <li>{@code digitalSignature}</li>
         *            <li>{@code nonRepudiation}</li>
         *            <li>{@code keyEncipherment}</li>
         *            <li>{@code dataEncipherment}</li>
         *            <li>{@code keyAgreement}</li>
         *            <li>{@code keyCertSign}</li>
         *            <li>{@code cRLSign}</li>
         *            <li>{@code encipherOnly}</li>
         *            <li>{@code decipherOnly}</li>
         *        </ul>
         *   </li>
         *   <li> {@code name: ExtendedKeyUsage} <br/>
         *        {@code value: usage(,usage)*} where {@code value} is a list of the allowed key purposes, where each
         *        {@code usage} value must be one of the following ({@code usage} values are case-sensitive):
         *        <ul>
         *            <li>{@code serverAuth}</li>
         *            <li>{@code clientAuth}</li>
         *            <li>{@code codeSigning}</li>
         *            <li>{@code emailProtection}</li>
         *            <li>{@code timeStamping}</li>
         *            <li>{@code OCSPSigning}</li>
         *            <li>any OID string</li>
         *        </ul>
         *   </li>
         *   <li> {@code name SubjectAlternativeName} <br/>
         *        {@code value: type:val(,type:val)*} where {@code value} is a list of {@code type:val} pairs, where
         *        {@code type} can be {@code EMAIL}, {@code URI}, {@code DNS}, {@code IP}, or {@code OID} and {@code val}
         *        is a string value for the {@code type}.
         *   </li>
         *   <br/>
         *   <li> {@code name: IssuerAlternativeName} <br/>
         *        {@code value: type:val(,type:val)*} where {@code value} is a list of {@code type:val} pairs, where
         *        {@code type} can be {@code EMAIL}, {@code URI}, {@code DNS}, {@code IP}, or {@code OID} and {@code val}
         *        is a string value for the {@code type}.
         *   </li>
         *   <br/>
         *   <li> {@code name: AuthorityInformationAccess} <br/>
         *        {@code value: method:location-type:location-value(,method:location-type:location-value)*} where
         *        {@code value} is a list of {@code method:location-type:location-value} triples, where {@code method} can be
         *        {@code ocsp}, {@code caIssuers}, or any OID and {@code location-type:location-value} can be any
         *        {@code type:val} pair as defined for the {@code SubjectAlternativeName} extension.
         *   </li>
         *   <br/>
         *   <li> {@code name: SubjectInformationAccess} <br/>
         *        {@code value: method:location-type:location-value(,method:location-type:location-value)*} where
         *        {@code value} is a list of {@code method:location-type:location-value} triples, where {@code method} can be
         *        {@code timeStamping}, {@code caRepository}, or any OID and {@code location-type:location-value} can be
         *        any {@code type:val} pair as defined for the {@code SubjectAlternativeName} extension.
         *   </li>
         * </ul>
         *
         * @param critical whether the extension should be marked as critical
         * @param extensionName the extension name (must not be {@code null})
         * @param extensionValue the extension value, as a string (must not be {@code null})
         * @return this builder instance
         * @throws IllegalArgumentException if an extension with the same name has already been added or if an
         * error occurs while attempting to add the extension
         */
        public Builder addExtension(boolean critical, String extensionName, String extensionValue) throws IllegalArgumentException {
            Assert.checkNotNullParam("name", extensionName);
            Assert.checkNotNullParam("value", extensionValue);
            return addExtension(getX509CertificateExtension(critical, extensionName, extensionValue));
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

            DEREncoder encoder = new DEREncoder();
            encodeCertificationRequest(encoder);
            return new PKCS10CertificateSigningRequest(this, encoder.getEncoded());
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
            DEREncoder tbsEncoder = new DEREncoder();
            encodeCertificationRequestInfo(tbsEncoder);

            byte[] signatureBytes;
            try {
                final Signature signature = Signature.getInstance(signatureAlgorithmName);
                signature.initSign(signingKey);
                signature.update(tbsEncoder.getEncoded());
                signatureBytes = signature.sign();
            } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
                throw log.certRequestInfoSigningFailed(e);
            }

            // CertificationRequest
            encoder.startSequence();
            encoder.writeEncoded(tbsEncoder.getEncoded());
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
            DEREncoder extensionEncoder = new DEREncoder();
            extension.encodeTo(extensionEncoder);
            encoder.encodeOctetString(extensionEncoder.getEncoded());
            encoder.endSequence();
        }

    }
}
