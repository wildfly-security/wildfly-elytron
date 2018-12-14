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

import static org.wildfly.security.x500.cert.ElytronMessages.log;
import static org.wildfly.security.x500.cert.util.KeyUtil.getDefaultCompatibleSignatureAlgorithmName;
import static org.wildfly.security.x500.cert.util.KeyUtil.getKeyIdentifier;
import static org.wildfly.security.x500.cert.CertUtil.getX509CertificateExtension;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;


/**
 * A self-signed X.509 certificate and the private key used to sign the certificate. This class can be used to
 * generate a PKCS #10 certificate signing request.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.2.0
 */
public final class SelfSignedX509CertificateAndSigningKey {

    private final X509Certificate selfSignedcertificate;
    private final PrivateKey signingKey;

    private SelfSignedX509CertificateAndSigningKey(Builder builder) {
        this.selfSignedcertificate = builder.selfSignedCertificate;
        this.signingKey = builder.signingKey;
    }

    /**
     * Get the self-signed X.509 certificate.
     *
     * @return the self-signed X.509 certificate
     */
    public X509Certificate getSelfSignedCertificate() {
        return selfSignedcertificate;
    }

    /**
     * Get the private key used to sign the self-signed X.509 certificate.
     *
     * @return the private key used to sign the self-signed X.509 certificate
     */
    public PrivateKey getSigningKey() {
        return signingKey;
    }

    /**
     * Generate a PKCS #10 certificate signing request using the self-signed X.509 certificate and the signing key.
     *
     * @return a PKCS #10 certificate signing request
     */
    public PKCS10CertificateSigningRequest generatePKCS10CertificateSigningRequest() {
        return PKCS10CertificateSigningRequest.builder()
                .setCertificate(selfSignedcertificate)
                .setSigningKey(signingKey)
                .build();
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
     * A {@code Builder} to configure and generate a {@code SelfSignedX509CertificateAndSigningKey}.
     * This {@code Builder} generates a key pair and then wraps the resulting public key into a
     * self-signed X.509 certificate.
     */
    public static class Builder {

        /**
         * The default key algorithm name.
         */
        public static final String DEFAULT_KEY_ALGORITHM_NAME = "DSA";

        /**
         * The default key size that will be used if the key algorithm name is EC.
         */
        public static final int DEFAULT_EC_KEY_SIZE = 256;

        /**
         * The default key size that will be used if the key algorithm name is not EC.
         */
        public static final int DEFAULT_KEY_SIZE = 2048;

        private static final int VERSION = 3; // X.509 v3
        private final Map<String, X509CertificateExtension> extensionsByOid = new LinkedHashMap<>();
        private String keyAlgorithmName;
        private String signatureAlgorithmName;
        private int keySize = -1;
        private X500Principal dn;
        private ZonedDateTime notValidBefore;
        private ZonedDateTime notValidAfter;
        private X509Certificate selfSignedCertificate;
        private PrivateKey signingKey;

        /**
         * Construct a new uninitialized instance.
         */
        Builder() {
        }

        /**
         * Set the key algorithm name to use when generating the key pair.
         *
         * @param keyAlgorithmName the key algorithm name to use when generating the key pair (must not be {@code null})
         * @return this builder instance
         */
        public Builder setKeyAlgorithmName(final String keyAlgorithmName) {
            Assert.checkNotNullParam("keyAlgorithmName", keyAlgorithmName);
            this.keyAlgorithmName = keyAlgorithmName;
            return this;
        }

        /**
         * Set the key size to use when generating the key pair.
         *
         * @param keySize the key size to use when generating the key pair
         * @return this builder instance
         */
        public Builder setKeySize(final int keySize) {
            this.keySize = keySize;
            return this;
        }

        /**
         * Set the signature algorithm name to use when signing the self-signed certificate.
         *
         * @param signatureAlgorithmName the signature algorithm to use when signing the self-signed certificate (must not be {@code null})
         * @return this builder instance
         */
        public Builder setSignatureAlgorithmName(final String signatureAlgorithmName) {
            Assert.checkNotNullParam("signatureAlgorithmName", signatureAlgorithmName);
            this.signatureAlgorithmName = signatureAlgorithmName;
            return this;
        }

        /**
         * Set the DN.
         *
         * @param dn the DN to use as both the subject DN and the issuer DN (must not be {@code null})
         * @return this builder instance
         */
        public Builder setDn(final X500Principal dn) {
            Assert.checkNotNullParam("dn", dn);
            this.dn = dn;
            return this;
        }

        /**
         * Add an X.509 certificate extension. If an extension with the same OID already exists, an exception is thrown.
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
         * Add an X.509 certificate extension using the given extension name and string value. If an extension with the same name already exists,
         * an exception is thrown. The following extension names and values are supported:
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
         * Add or replace an X.509 certificate extension. If an extension with the same OID already exists, it is replaced
         * and returned.
         *
         * @param extension the extension to add (must not be {@code null})
         * @return the existing extension or {@code null} if no other extension with the same OID existed
         */
        public X509CertificateExtension addOrReplaceExtension(X509CertificateExtension extension) {
            Assert.checkNotNullParam("extension", extension);
            final String oid = extension.getId();
            Assert.checkNotNullParam("extension.getOid()", oid);
            return extensionsByOid.put(oid, extension);
        }

        /**
         * Add or replace an X.509 certificate extension. If an extension with the same name already exists, it is replaced
         * and returned. See {@link SelfSignedX509CertificateAndSigningKey.Builder#addExtension(boolean, String, String)}
         * for the supported extension names and values.
         *
         * @param critical whether the extension should be marked as critical
         * @param extensionName the extension name (must not be {@code null})
         * @param extensionValue the extension value, as a string (must not be {@code null})
         * @return the existing extension or {@code null} if no other extension with the same OID existed or if an
         * error occurs while attempting to add the extension
         */
        public X509CertificateExtension addOrReplaceExtension(boolean critical, String extensionName, String extensionValue) {
            Assert.checkNotNullParam("name", extensionName);
            return addOrReplaceExtension(getX509CertificateExtension(critical, extensionName, extensionValue));
        }

        /**
         * Remove the X.509 extension with the given OID, if it is registered.
         *
         * @param oid the OID of the extension to remove (must not be {@code null})
         * @return the extension or {@code null} if no extension with the same OID existed
         */
        public X509CertificateExtension removeExtension(String oid) {
            Assert.checkNotNullParam("oid", oid);
            return extensionsByOid.remove(oid);
        }

        /**
         * Set the not-valid-before date.
         *
         * @param notValidBefore the not-valid-before date (must not be {@code null})
         * @return this builder instance
         */
        public Builder setNotValidBefore(final ZonedDateTime notValidBefore) {
            Assert.checkNotNullParam("notValidBefore", notValidBefore);
            this.notValidBefore = notValidBefore;
            return this;
        }

        /**
         * Set the not-valid-after date.
         *
         * @param notValidAfter the not-valid-after date (must not be {@code null})
         * @return this builder instance
         */
        public Builder setNotValidAfter(final ZonedDateTime notValidAfter) {
            Assert.checkNotNullParam("notValidAfter", notValidAfter);
            this.notValidAfter = notValidAfter;
            return this;
        }

        /**
         * Attempt to generate a key pair and wrap the resulting public key into a self-signed X.509 certificate.
         *
         * @return the self-signed X.509 certificate and signing key
         * @throws IllegalArgumentException if a required builder parameter is missing or invalid or if an
         * error occurs while attempting to generate the self-signed X.509 certificate
         */
        public SelfSignedX509CertificateAndSigningKey build() throws IllegalArgumentException {
            if (dn == null) {
                throw log.noDnGiven();
            }
            if (keyAlgorithmName == null) {
                keyAlgorithmName = DEFAULT_KEY_ALGORITHM_NAME;
            }
            if (keySize == -1) {
                if (keyAlgorithmName.equals("EC")) {
                    keySize = DEFAULT_EC_KEY_SIZE;
                } else {
                    keySize = DEFAULT_KEY_SIZE;
                }
            }

            try {
                // generate a key pair
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithmName);
                keyPairGenerator.initialize(keySize, new SecureRandom());
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                signingKey = keyPair.getPrivate();
                if (signatureAlgorithmName == null) {
                    signatureAlgorithmName = getDefaultCompatibleSignatureAlgorithmName(signingKey.getAlgorithm(), keySize);
                    if (signatureAlgorithmName == null) {
                        throw log.unableToDetermineDefaultCompatibleSignatureAlgorithmName(signingKey.getAlgorithm());
                    }
                }

                // add the Subject Key Identifier extension if it's not already present
                final X509CertificateExtension subjectKeyIdentifierExtension = new SubjectKeyIdentifierExtension(getKeyIdentifier(keyPair.getPublic()));
                addExtension(subjectKeyIdentifierExtension);

                // generate the self-signed certificate
                X509CertificateBuilder certificateBuilder = new X509CertificateBuilder();
                certificateBuilder.setIssuerDn(dn);
                certificateBuilder.setSubjectDn(dn);
                certificateBuilder.setPublicKey(keyPair.getPublic());
                certificateBuilder.setSigningKey(signingKey);
                certificateBuilder.setSignatureAlgorithmName(signatureAlgorithmName);
                certificateBuilder.setVersion(VERSION);
                BigInteger serialNumber = new BigInteger(64, new SecureRandom());
                certificateBuilder.setSerialNumber(serialNumber);
                for (X509CertificateExtension extension : extensionsByOid.values()) {
                    certificateBuilder.addExtension(extension);
                }
                if (notValidBefore != null) {
                    certificateBuilder.setNotValidBefore(notValidBefore);
                }
                if (notValidAfter != null) {
                    certificateBuilder.setNotValidAfter(notValidAfter);
                }
                selfSignedCertificate = certificateBuilder.build();
                return new SelfSignedX509CertificateAndSigningKey(this);
            } catch (Exception e) {
                throw log.selfSignedCertificateGenerationFailed(e);
            }
        }
    }
}
