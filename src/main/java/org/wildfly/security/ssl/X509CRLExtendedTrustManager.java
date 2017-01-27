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

package org.wildfly.security.ssl;

import static org.wildfly.common.Assert.checkMinimumParameter;
import static org.wildfly.common.Assert.checkNotNullParam;

import java.io.InputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;
import java.util.stream.Stream;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.wildfly.security._private.ElytronMessages;

/**
 * Extension to the {@link X509TrustManager} interface to support CRL verification.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class X509CRLExtendedTrustManager extends X509ExtendedTrustManager {

    private static final int DEFAULT_MAX_CERT_PATH_LENGTH = 5;

    private final X509TrustManager trustManager;
    private final X509Certificate[] acceptedIssuers;

    /**
     * Creates a new instance.
     *
     * @param trustStore a {@link KeyStore} with the trusted certificates (must not be {@code null})
     * @param trustManagerFactory the trust manager factory
     * @param crlStream the input stream pointing to a certificate revocation list (may be {@code null}). The stream will be automatically closed after the invocation
     * @param maxCertPath the maximum number of non-self-issued intermediate certificates that may exist in a certification path. The value must be equal or greater than 1.
     * @param acceptedIssuers an array of certificate authority certificates which are trusted for authenticating peers (may be {@code null}).
     */
    public X509CRLExtendedTrustManager(KeyStore trustStore, TrustManagerFactory trustManagerFactory, InputStream crlStream, int maxCertPath, X509Certificate[] acceptedIssuers) {
        checkNotNullParam("trustStore", trustStore);
        checkNotNullParam("trustManagerFactory", trustManagerFactory);
        checkMinimumParameter("maxCertPath", 1, maxCertPath);
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustStore, new X509CertSelector());

            if (crlStream != null) {
                CertStoreParameters csp = new CollectionCertStoreParameters(getCRLs(crlStream));
                CertStore store = CertStore.getInstance("Collection", csp);
                params.addCertStore(store);
            }

            params.setRevocationEnabled(true);
            params.setMaxPathLength(maxCertPath);

            trustManagerFactory.init(new CertPathTrustManagerParameters(params));

            X509TrustManager[] trustManagers = Stream.of(trustManagerFactory.getTrustManagers()).map(trustManager -> trustManager instanceof X509TrustManager ? (X509TrustManager) trustManager : null).filter(Objects::nonNull).toArray(X509TrustManager[]::new);

            if (trustManagers.length == 0) {
                throw ElytronMessages.log.noDefaultTrustManager();
            }

            this.trustManager = trustManagers[0];
        } catch (GeneralSecurityException e) {
            throw ElytronMessages.log.sslErrorCreatingTrustManager(getClass().getName(), e);
        }

        this.acceptedIssuers = acceptedIssuers;
    }

    /**
     * Creates a new instance using with a default trust manager factory. The factory's algorithm is {@link TrustManagerFactory#getDefaultAlgorithm()}.
     *
     * @param trustStore a {@link KeyStore} with the trusted certificates (must not be {@code null})
     * @param crlStream the input stream pointing to a certificate revocation list (may be {@code null}). The stream will be automatically closed after the invocation
     *
     * @throws NoSuchAlgorithmException in case the default trust manager factory can not be obtained
     */
    public X509CRLExtendedTrustManager(KeyStore trustStore, InputStream crlStream) throws NoSuchAlgorithmException {
        this(trustStore, TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()), crlStream, DEFAULT_MAX_CERT_PATH_LENGTH, null);
    }

    /**
     * <p>Creates a new instance using with a default trust manager factory. The factory's algorithm is {@link TrustManagerFactory#getDefaultAlgorithm()}.
     *
     * <p>When using this constructor, the instance is going to obtain CRLs from the distribution points
     * within the certificates being validated. Make sure you have system property <code>com.sun.security.enableCRLDP</code> set.
     *
     * @param trustStore a {@link KeyStore} with the trusted certificates (must not be {@code null})
     * @throws NoSuchAlgorithmException in case the default trust manager factory can not be obtained
     */
    public X509CRLExtendedTrustManager(KeyStore trustStore) throws NoSuchAlgorithmException {
        this(trustStore, null);
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
    public X509Certificate[] getAcceptedIssuers() {
        return acceptedIssuers;
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
}
