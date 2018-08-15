/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.acme;

import static org.wildfly.security._private.ElytronMessages.acme;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.x500.cert.util.KeyUtil.getDefaultCompatibleSignatureAlgorithmName;
import static org.wildfly.security.x500.cert.acme.Acme.getAlgHeaderFromSignatureAlgorithm;

import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.X500AttributeTypeAndValue;
import org.wildfly.security.x500.X500PrincipalBuilder;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.util.KeyUtil;

/**
 * A class that represents an <a href="https://www.ietf.org/id/draft-ietf-acme-acme-14.txt">Automatic Certificate
 * Management Environment (ACME)</a> account.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.5.0
 */
public final class AcmeAccount {

    private String[] contactUrls;
    private boolean termsOfServiceAgreed;
    private String serverUrl;
    private String stagingServerUrl;
    private PrivateKey privateKey;
    private X509Certificate certificate;
    private X500Principal dn;
    private String algHeader;
    private String signatureAlgorithm;
    private int keySize;
    private String keyAlgorithmName;
    private String accountUrl;
    private HashMap<AcmeResource, URL> resourceUrls = new HashMap<>(AcmeResource.values().length);
    private HashMap<AcmeResource, URL> stagingResourceUrls = new HashMap<>(AcmeResource.values().length);
    private byte[] nonce;

    private AcmeAccount(Builder builder) {
        this.contactUrls = builder.contactUrls;
        this.termsOfServiceAgreed = builder.termsOfServiceAgreed;
        this.serverUrl = builder.serverUrl;
        this.stagingServerUrl = builder.stagingServerUrl;
        this.privateKey = builder.privateKey;
        this.certificate = builder.certificate;
        this.algHeader = builder.algHeader;
        this.signatureAlgorithm = builder.signatureAlgorithm;
        this.keySize = builder.keySize;
        this.keyAlgorithmName = builder.keyAlgorithmName;
        this.dn = builder.dn;
    }

    /**
     * Get the account contact URLs.
     *
     * @return the contact URLs
     */
    public String[] getContactUrls() {
        return contactUrls;
    }

    /**
     * Set the account contact URLs.
     *
     * @param contactUrls the contact URLs (must not be {@code null})
     */
    public void setContactUrls(String[] contactUrls) {
        Assert.checkNotNullParam("contactUrls", contactUrls);
        this.contactUrls = contactUrls;
    }

    /**
     * Return whether or not the ACME server's terms of service have been agreed to.
     *
     * @return whether or not the ACME server's terms of service have been agreed to
     */
    public boolean isTermsOfServiceAgreed() {
        return termsOfServiceAgreed;
    }

    /**
     * Set whether the terms of services have been agreed to.
     *
     * @param termsOfServiceAgreed whether or not the ACME server's terms of service have been agreed to
     */
    public void setTermsOfServiceAgreed(boolean termsOfServiceAgreed) {
        Assert.checkNotNullParam("termsOfServiceAgreed", termsOfServiceAgreed);
        this.termsOfServiceAgreed = termsOfServiceAgreed;
    }

    /**
     * Get the ACME server URL.
     *
     * @return the ACME server URL
     */
    public String getServerUrl() {
        return serverUrl;
    }

    /**
     * Get the ACME server URL.
     *
     * @param staging whether or not the ACME staging server should be returned
     * @return the ACME server URL
     */
    public String getServerUrl(boolean staging) {
        if (staging) {
            return stagingServerUrl;
        } else {
            return serverUrl;
        }
    }

    /**
     * Get the ACME staging server URL.
     *
     * @return the ACME staging server URL
     */
    public String getStagingServerUrl() {
        return stagingServerUrl;
    }

    /**
     * Get the account private key.
     *
     * @return the account private key
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Get the account public key.
     *
     * @return the account public key
     */
    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    /**
     * Get the X.509 certificate that contains the account public key.
     *
     * @return the X.509 certificate that contains the account public key
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Get the DN from the X.509 certificate that contains the account public key.
     */
    public X500Principal getDn() {
        return dn;
    }

    /**
     * Get the JWS "alg" header parameter value for this account.
     *
     * @return the JWS "alg" header parameter value for this account
     */
    public String getAlgHeader() {
        return algHeader;
    }

    /**
     * Get a signature instance for this account.
     *
     * @return a signature instance for this account
     */
    public Signature getSignature() {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            return signature;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw acme.unableToCreateAcmeSignature(e);
        }
    }

    /**
     * Get the key size.
     *
     * @return the key size
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Get the key algorithm name.
     *
     * @return the key algorithm name
     */
    public String getKeyAlgorithmName() {
        return keyAlgorithmName;
    }

    /**
     * Return the account location URL or {@code null} if this account has not yet been
     * successfully registered with the ACME server.
     *
     * @return the account location URL or {@code null} if this account has not yet been
     * successfully registered with the ACME server
     */
    public String getAccountUrl() {
        return accountUrl;
    }

    /**
     * Set the account location URL provided by the ACME server.
     *
     * @param accountUrl the account location URL (must not be {@code null})
     */
    public void setAccountUrl(String accountUrl) {
        Assert.checkNotNullParam("accountUrl", accountUrl);
        this.accountUrl = accountUrl;
    }

    /**
     * Get the URL for the given ACME resource.
     *
     * @param resource the ACME resource (must not be {@code null})
     * @param staging whether or not the ACME staging server should be used
     * @return the URL for the given ACME resource
     */
    public URL getResourceUrl(AcmeResource resource, boolean staging) {
        Assert.checkNotNullParam("resource", resource);
        return getResourceUrls(staging).get(resource);
    }

    /**
     * Get the ACME resource URLs.
     *
     * @param staging whether or not the ACME staging server should be used
     * @return the ACME resource URLs
     */
    public Map<AcmeResource, URL> getResourceUrls(boolean staging) {
        return staging ? stagingResourceUrls : resourceUrls;
    }

    /**
     * Get the current nonce for this account.
     *
     * @return the current nonce for this account
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Set the new nonce for this account.
     *
     * @param nonce the new nonce for this account (must not be {@code null})
     */
    public void setNonce(byte[] nonce) {
        Assert.checkNotNullParam("nonce", nonce);
        this.nonce = nonce;
    }

    /**
     * Change the certificate and private key associated with this account.
     *
     * @param certificate the new certificate (must not be {@code null})
     * @param privateKey the new private key (must not be {@code null})
     */
    public void changeCertificateAndPrivateKey(X509Certificate certificate, PrivateKey privateKey) {
        Assert.checkNotNullParam("certificate", certificate);
        Assert.checkNotNullParam("privateKey", privateKey);
        this.certificate = certificate;
        this.privateKey = privateKey;
        keySize = KeyUtil.getKeySize(privateKey);
        keyAlgorithmName = privateKey.getAlgorithm();
        signatureAlgorithm = getDefaultCompatibleSignatureAlgorithmName(privateKey);
        algHeader = getAlgHeaderFromSignatureAlgorithm(signatureAlgorithm);
        dn = certificate.getSubjectX500Principal();
    }

    /**
     * Construct a new builder instance.
     *
     * @return the new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        /**
         * The default account key algorithm name.
         */
        public static final String DEFAULT_ACCOUNT_KEY_ALGORITHM_NAME = "RSA";

        /**
         * The default account key size that will be used if the key algorithm name is not EC.
         */
        public static final int DEFAULT_ACCOUNT_KEY_SIZE = 2048;

        /**
         * The default account key size that will be used if the key algorithm name is EC.
         */
        public static final int DEFAULT_ACCOUNT_EC_KEY_SIZE = 256;

        static final String ACCOUNT_KEY_NAME = "account.key";

        private String[] contactUrls;
        private boolean termsOfServiceAgreed;
        private String serverUrl;
        private String stagingServerUrl;
        private PrivateKey privateKey;
        private X509Certificate certificate;
        private X500Principal dn;
        private String keyAlgorithmName;
        private int keySize = -1;
        private String algHeader;
        private String signatureAlgorithm;

        /**
         * Construct a new uninitialized instance.
         */
        Builder() {
        }

        /**
         * Set the contact URLs.
         *
         * @param contactUrls the contact URLs (must not be {@code null})
         * @return this builder instance
         */
        public Builder setContactUrls(final String[] contactUrls) {
            Assert.checkNotNullParam("contactUrls", contactUrls);
            this.contactUrls = contactUrls;
            return this;
        }

        /**
         * Set if the terms of service of the ACME server have been agreed to.
         *
         * @param termsOfServiceAgreed whether or not the ACME server's terms of service have been agreed to
         * @return this builder instance
         */
        public Builder setTermsOfServiceAgreed(final boolean termsOfServiceAgreed) {
            Assert.checkNotNullParam("termsOfServiceAgreed", termsOfServiceAgreed);
            this.termsOfServiceAgreed = termsOfServiceAgreed;
            return this;
        }

        /**
         * Set the URL of the ACME server endpoint.
         *
         * @param serverUrl the ACME server endpoint URL (must not be {@code null})
         * @return this builder instance
         */
        public Builder setServerUrl(final String serverUrl) {
            Assert.checkNotNullParam("serverUrl", serverUrl);
            this.serverUrl = serverUrl;
            return this;
        }

        /**
         * Set the URL of the ACME staging server endpoint.
         *
         * @param stagingServerUrl the ACME staging server endpoint URL (must not be {@code null})
         * @return this builder instance
         */
        public Builder setStagingServerUrl(final String stagingServerUrl) {
            Assert.checkNotNullParam("stagingServerUrl", stagingServerUrl);
            this.stagingServerUrl = stagingServerUrl;
            return this;
        }

        /**
         * Set the key algorithm name to use when generating the account key pair.
         *
         * @param keyAlgorithmName the key algorithm name to use when generating the account key pair (must not be {@code null})
         * @return this builder instance
         */
        public Builder setKeyAlgorithmName(final String keyAlgorithmName) {
            Assert.checkNotNullParam("keyAlgorithmName", keyAlgorithmName);
            this.keyAlgorithmName = keyAlgorithmName;
            return this;
        }

        /**
         * Set the key size to use when generating the account key pair.
         *
         * @param keySize the key size to use when generating the account key pair
         * @return this builder instance
         */
        public Builder setKeySize(final int keySize) {
            this.keySize = keySize;
            return this;
        }

        /**
         * Set the DN to use when generating the account key pair.
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
         * Set the account key pair.
         *
         * @param certificate the certificate (must not be {@code null})
         * @param privateKey the key (must not be {@code null})
         * @return this builder instance
         */
        public Builder setKey(final X509Certificate certificate, final PrivateKey privateKey) {
            Assert.checkNotNullParam("certificate", certificate);
            Assert.checkNotNullParam("privateKey", privateKey);
            this.certificate = certificate;
            this.privateKey = privateKey;
            return this;
        }

        /**
         * Create an ACME account.
         *
         * @return the newly created ACME account
         * @throws IllegalArgumentException if a required builder parameter is missing or invalid
         */
        public AcmeAccount build() throws IllegalArgumentException {
            if (serverUrl == null) {
                throw log.noAcmeServerUrlGiven();
            }
            if (certificate != null && privateKey != null) {
                keySize = KeyUtil.getKeySize(privateKey);
                if (keySize == -1) {
                    throw acme.unableToDetermineKeySize();
                }
                keyAlgorithmName = privateKey.getAlgorithm();
                signatureAlgorithm = getDefaultCompatibleSignatureAlgorithmName(privateKey);
                if (signatureAlgorithm == null) {
                    throw log.unableToDetermineDefaultCompatibleSignatureAlgorithmName(privateKey.getAlgorithm());
                }
                algHeader = getAlgHeaderFromSignatureAlgorithm(signatureAlgorithm);
                dn = certificate.getSubjectX500Principal();
            } else {
                // generate the account key pair
                if (keyAlgorithmName == null) {
                    keyAlgorithmName = DEFAULT_ACCOUNT_KEY_ALGORITHM_NAME;
                }
                if (dn == null) {
                    X500PrincipalBuilder principalBuilder = new X500PrincipalBuilder();
                    principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String(ACCOUNT_KEY_NAME)));
                    dn = principalBuilder.build();
                }
                if (keySize == -1) {
                    if (keyAlgorithmName.equals("EC")) {
                        keySize = DEFAULT_ACCOUNT_EC_KEY_SIZE;
                    } else {
                        keySize = DEFAULT_ACCOUNT_KEY_SIZE;
                    }
                }
                try {
                    SelfSignedX509CertificateAndSigningKey certificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                            .setKeySize(keySize)
                            .setKeyAlgorithmName(keyAlgorithmName)
                            .setDn(dn)
                            .build();
                    privateKey = certificateAndSigningKey.getSigningKey();
                    certificate = certificateAndSigningKey.getSelfSignedCertificate();
                    signatureAlgorithm = getDefaultCompatibleSignatureAlgorithmName(privateKey);
                    if (signatureAlgorithm == null) {
                        throw log.unableToDetermineDefaultCompatibleSignatureAlgorithmName(privateKey.getAlgorithm());
                    }
                    algHeader = getAlgHeaderFromSignatureAlgorithm(signatureAlgorithm);
                } catch (Exception e) {
                    throw acme.acmeAccountKeyPairGenerationFailed(e);
                }
            }
            return new AcmeAccount(this);
        }
    }
}
