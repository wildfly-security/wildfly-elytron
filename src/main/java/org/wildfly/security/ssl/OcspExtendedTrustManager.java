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

package org.wildfly.security.ssl;

import java.net.Socket;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.wildfly.common.Assert;
import org.wildfly.security.x500.cert.ocsp.OcspCachingChecker;
import org.wildfly.security.x500.cert.ocsp.OcspChainVerifier;
import org.wildfly.security.x500.cert.ocsp.OcspChecker;
import org.wildfly.security.x500.cert.ocsp.OcspOnlineChecker;

/**
 * An {@link javax.net.ssl.TrustManager} checking certificates revocation status using OCSP.
 * Other checks are delegated to another TrustManager.
 */
public class OcspExtendedTrustManager extends X509ExtendedTrustManager {

    private final X509TrustManager delegate;
    private final OcspChainVerifier verifier;

    private OcspExtendedTrustManager(X509TrustManager delegate, OcspChainVerifier verifier) {
        this.delegate = delegate;
        this.verifier = verifier;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
        verifier.checkChain(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
        verifier.checkChain(chain);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager)delegate).checkClientTrusted(chain, authType, socket);
        } else {
            throw new UnsupportedOperationException();
        }
        verifier.checkChain(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager)delegate).checkServerTrusted(chain, authType, socket);
        } else {
            throw new UnsupportedOperationException();
        }
        verifier.checkChain(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager)delegate).checkClientTrusted(chain, authType, sslEngine);
        } else {
            throw new UnsupportedOperationException();
        }
        verifier.checkChain(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager)delegate).checkServerTrusted(chain, authType, sslEngine);
        } else {
            throw new UnsupportedOperationException();
        }
        verifier.checkChain(chain);
    }

    /**
     * Get a builder.
     * @return a builder
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private X509TrustManager delegate;
        private URL responder;
        private Collection<X509Certificate> trusted;
        private boolean acceptUnknownCertificates = false;
        private boolean acceptWhenStatusUnavailable = false;
        private int connectionTimeout = 10000;
        private boolean cacheEnabled = false;
        private long cacheMaxAge = 60*1000;
        private int cacheMaxEntries = 16;

        Builder() {}

        /**
         * Set the delegate trust manager.
         *
         * @param delegate the delegate trust manager (must not be {@code null})
         * @return this builder instance
         */
        public Builder setDelegate(X509TrustManager delegate) {
            Assert.checkNotNullParam("delegate", delegate);
            this.delegate = delegate;
            return this;
        }

        /**
         * Set the OCSP responder.
         *
         * @param responder the OCSP responder ({@code null} to obtain a responder from the certificate)
         * @return this builder instance
         */
        public Builder setResponder(URL responder) {
            this.responder = responder;
            return this;
        }

        /**
         * Set trusted certificates for OCSP responders.
         *
         * @param trusted trusted certificates
         * @return this builder instance
         */
        public Builder setTrusted(Collection<X509Certificate> trusted) {
            this.trusted = trusted;
            return this;
        }

        /**
         * Set whether should be certificate with UNKNOWN OCSP response accepted.
         *
         * @param acceptUnknownCertificates whether should be certificate with UNKNOWN OCSP response accepted
         * @return this builder instance
         */
        public Builder setAcceptUnknownCertificates(boolean acceptUnknownCertificates) {
            this.acceptUnknownCertificates = acceptUnknownCertificates;
            return this;
        }

        /**
         * Set whether should be certificate accepted when it is not possible to contact an OCSP server.
         *
         * @param acceptWhenStatusUnavailable whether should be certificate accepted when it is not possible to contact an OCSP server
         * @return this builder instance
         */
        public Builder setAcceptWhenStatusUnavailable(boolean acceptWhenStatusUnavailable) {
            this.acceptWhenStatusUnavailable = acceptWhenStatusUnavailable;
            return this;
        }

        /**
         * Set timeout for contacting an OCSP server.
         *
         * @param connectionTimeout the timeout value in milliseconds (zero for infinite timeout)
         * @return this builder instance
         */
        public Builder setConnectionTimeout(int connectionTimeout) {
            this.connectionTimeout = connectionTimeout;
            return this;
        }

        /**
         * Set whether should be certificates status cache used.
         *
         * @param cacheEnabled whether should be certificates status cache used
         * @return this builder instance
         */
        public Builder setCacheEnabled(boolean cacheEnabled) {
            this.cacheEnabled = cacheEnabled;
            return this;
        }

        /**
         * Set maximum age of certificates in the cache.
         *
         * @param cacheMaxAge maximum age in miliseconds
         * @return this builder instance
         */
        public Builder setCacheMaxAge(long cacheMaxAge) {
            this.cacheMaxAge = cacheMaxAge;
            return this;
        }

        /**
         * Set maximum amount of certificates in the cache.
         *
         * @param cacheMaxEntries maximum amount of certificates in the cache
         * @return this builder instance
         */
        public Builder setCacheMaxEntries(int cacheMaxEntries) {
            this.cacheMaxEntries = cacheMaxEntries;
            return this;
        }

        public OcspExtendedTrustManager build() {
            OcspChecker checker = new OcspOnlineChecker(connectionTimeout);
            if (cacheEnabled) {
                checker = new OcspCachingChecker(checker, cacheMaxAge, cacheMaxEntries);
            }
            OcspChainVerifier verifier = new OcspChainVerifier(checker, responder, trusted, acceptUnknownCertificates, acceptWhenStatusUnavailable);
            return new OcspExtendedTrustManager(delegate, verifier);
        }
    }

}
