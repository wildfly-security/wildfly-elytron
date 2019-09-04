/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.ssl;

import org.wildfly.security.x500.X500;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXReason;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import static org.wildfly.common.Assert.checkNotNullParam;

/**
 * Extension to the {@link X509TrustManager} interface to support OCSP and CRL verification.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class X509RevocationTrustManager extends X509ExtendedTrustManager {

    private static final int DEFAULT_MAX_CERT_PATH_LENGTH = 5;

    private final X509Certificate[] acceptedIssuers;
    private final X509TrustManager trustManager;

    private X509RevocationTrustManager(Builder builder) {

        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(builder.trustStore, new X509CertSelector());

            if (builder.crlStream != null) {
                CertStoreParameters csp = new CollectionCertStoreParameters(getCRLs(builder.crlStream));
                CertStore store = CertStore.getInstance("Collection", csp);
                params.addCertStore(store);
            }

            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
            PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();

            if (builder.ocspResponderCert != null) {
                rc.setOcspResponderCert(builder.ocspResponderCert);
            }

            EnumSet<PKIXRevocationChecker.Option> options = EnumSet.noneOf(PKIXRevocationChecker.Option.class);
            if (builder.onlyEndEntity) {
                options.add(PKIXRevocationChecker.Option.ONLY_END_ENTITY);
            }
            if (builder.preferCrls) {
                options.add(PKIXRevocationChecker.Option.PREFER_CRLS);
            }
            if (builder.softFail) {
                options.add(PKIXRevocationChecker.Option.SOFT_FAIL);
            }
            if (builder.noFallback) {
                options.add(PKIXRevocationChecker.Option.NO_FALLBACK);
            }

            rc.setOptions(options);
            rc.setOcspResponder(builder.responderUri);
            params.setRevocationEnabled(true);
            params.addCertPathChecker(rc);

            PKIXCertPathChecker maxPathLengthChecker = new MaxPathLengthChecker(builder.maxCertPath);
            params.addCertPathChecker(maxPathLengthChecker);
            params.setMaxPathLength(builder.maxCertPath);

            builder.trustManagerFactory.init(new CertPathTrustManagerParameters(params));

            X509TrustManager[] trustManagers = Stream.of(builder.trustManagerFactory.getTrustManagers()).map(trustManager -> trustManager instanceof X509TrustManager ? (X509TrustManager) trustManager : null).filter(Objects::nonNull).toArray(X509TrustManager[]::new);

            if (trustManagers.length == 0) {
                throw ElytronMessages.log.noDefaultTrustManager();
            }

            this.trustManager = trustManagers[0];
        } catch(GeneralSecurityException e) {
            throw ElytronMessages.log.sslErrorCreatingRevocationTrustManager(builder.trustManagerFactory.getAlgorithm(), e);
        }

        if (builder.acceptedIssuers != null) {
            this.acceptedIssuers = builder.acceptedIssuers;
        } else {
            this.acceptedIssuers = X500.NO_CERTIFICATES;
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return acceptedIssuers;
    }

    private Collection<? extends CRL> getCRLs(InputStream crlStream) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try {
            return cf.generateCRLs(crlStream);
        } finally {
            try {
                crlStream.close();
            } catch (Exception ignore) {}
        }
    }

    public static class Builder {
        private X509Certificate[] acceptedIssuers = null;
        private KeyStore trustStore = null;
        private TrustManagerFactory trustManagerFactory = null;
        private URI responderUri = null;
        private InputStream crlStream = null;
        private X509Certificate ocspResponderCert = null;
        private int maxCertPath = DEFAULT_MAX_CERT_PATH_LENGTH;
        private boolean preferCrls = false;
        private boolean onlyEndEntity = false;
        private boolean softFail = false;
        private boolean noFallback = false;


        private Builder() {}

        /**
         * Set an array of certificate authority certificates which are trusted for authenticating peers (may be {@code null})
         *
         * @param acceptedIssuers array of accepted issuers
         * @return this Builder for subsequent changes
         */
        public Builder setAcceptedIssuers(X509Certificate[] acceptedIssuers) {
            this.acceptedIssuers = acceptedIssuers;
            return this;
        }

        /**
         * Set a {@link KeyStore} with the trusted certificates (must not be {@code null})
         *
         * @param trustStore keystore with trusted certificates
         * @return this Builder for subsequent changes
         */
        public Builder setTrustStore(KeyStore trustStore) {
            this.trustStore = trustStore;
            return this;
        }

        /**
         * Set a {@link TrustManagerFactory}
         *
         * @param trustManagerFactory the trust manager factory
         * @return this Builder for subsequent changes
         */
        public Builder setTrustManagerFactory(TrustManagerFactory trustManagerFactory) {
            this.trustManagerFactory = trustManagerFactory;
            return this;
        }

        /**
         * Set an OCSP Responder {@link URI} to override those extracted from certificates.
         *
         * @param responderURI the responder URI
         * @return this Builder for subsequent changes
         */
        public Builder setResponderURI(URI responderURI) {
            this.responderUri = responderURI;
            return this;
        }

        /**
         * Set the input stream pointing to a certificate revocation list (may be {@code null}). The stream will be automatically closed after the invocation
         *
         * @param crlStream the input stream
         * @return this Builder for subsequent changes
         */
        public Builder setCrlStream(InputStream crlStream) {
            this.crlStream = crlStream;
            return this;
        }

        /**
         * Set the maximum number of non-self-issued intermediate certificates that may exist in a certification path. The value must be equal or greater than 1.
         *
         * @param maxCertPath the maximum cert path
         * @return this Builder for subsequent changes
         */
        public Builder setMaxCertPath(int maxCertPath) {
            this.maxCertPath = maxCertPath;
            return this;
        }

        /**
         * Set if CRL revocation should be executed before OCSP. Default false
         *
         * @param preferCrls true if CRLs should be preferred
         * @return this Builder for subsequent changes
         */
        public Builder setPreferCrls(boolean preferCrls) {
            this.preferCrls = preferCrls;
            return this;
        }

        /**
         * Set if only leaf certificate revocation should be checked. Default false
         *
         * @param onlyEndEntity true if only leaf certificate should be checked
         * @return this Builder for subsequent changes
         */
        public Builder setOnlyEndEntity(boolean onlyEndEntity) {
            this.onlyEndEntity = onlyEndEntity;
            return this;
        }

        /**
         * Set if certificate should be allowed in case the revocation status cannot be obtained. Default false
         *
         * @param softFail true if unknown revocation status is accepted
         * @return this Builder for subsequent changes
         */
        public Builder setSoftFail(boolean softFail) {
            this.softFail = softFail;
            return this;
        }

        /**
         * Set if only one method of obtaining revocation status should be used. Default false
         *
         * @param noFallback true if only one method of obtaining revocation status should be used
         * @return this Builder for subsequent changes
         */
        public Builder setNoFallback(boolean noFallback) {
            this.noFallback = noFallback;
            return this;
        }

        /**
         * Set OCSP responder's certificate. By default issuer certificate of certificate being validated is used.
         *
         * @param ocspResponderCert OCSP responder certificate
         * @return this Builder for subsequent changes
         */
        public Builder setOcspResponderCert(X509Certificate ocspResponderCert) {
            this.ocspResponderCert = ocspResponderCert;
            return this;
        }

        public X509RevocationTrustManager build() {
            checkNotNullParam("trustStore", trustStore);
            checkNotNullParam("trustManagerFactory", trustManagerFactory);

            return new X509RevocationTrustManager(this);
        }
    }

    /**
     * Create new X509RevocationTtustManager.Builder instance
     * @return new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }


    /**
     * PKIXCertPathChecker to check if a cert path being validated is longer than maxPathLength specified
     */

    private class MaxPathLengthChecker extends PKIXCertPathChecker {
        private int maxPathLength;
        private int i;

        MaxPathLengthChecker(int maxPathLength) {
            this.maxPathLength = maxPathLength;
        }

        /*
         * Initialize checker
         */
        public void init(boolean forward) {
            i = 0;
        }

        @Override
        public boolean isForwardCheckingSupported() {
            return false;
        }

        @Override
        public Set<String> getSupportedExtensions() {
            return null;
        }

        public void check(Certificate cert, Collection unresolvedCritExts)
                throws CertPathValidatorException {
            X509Certificate currCert = (X509Certificate) cert;
            i++;
            checkCertPathLength(currCert);
        }

        private void checkCertPathLength(X509Certificate currCert) throws CertPathValidatorException {
            X500Principal subject = currCert.getSubjectX500Principal();
            X500Principal issuer = currCert.getIssuerX500Principal();

            int pathLenConstraint = -1;
            if (currCert.getVersion() < 3) {    // version 1 or version 2
                if (i == 1) {
                    if (subject.equals(issuer)) {
                        pathLenConstraint = Integer.MAX_VALUE;
                    }
                }
            } else {
                pathLenConstraint = currCert.getBasicConstraints();
            }

            if (pathLenConstraint == -1) {
                pathLenConstraint = maxPathLength;
            }

            if (!subject.equals(issuer)) {
                if (pathLenConstraint < i) {
                    throw new CertPathValidatorException
                            ("check failed: pathLenConstraint violated - "
                                    + "this cert must be the last cert in the "
                                    + "certification path", null, null, -1,
                                    PKIXReason.PATH_TOO_LONG);
                }
            }
            if (pathLenConstraint < maxPathLength)
                maxPathLength = pathLenConstraint;
        }
    }
}
