/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class WrappingX509ExtendedTrustManager extends X509ExtendedTrustManager implements X509TrustManager {

    private final X509TrustManager delegate;

    WrappingX509ExtendedTrustManager(final X509TrustManager delegate) {
        this.delegate = delegate;
    }

    public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s, final Socket socket) throws CertificateException {
        delegate.checkClientTrusted(x509Certificates, s);
    }

    public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s, final Socket socket) throws CertificateException {
        delegate.checkServerTrusted(x509Certificates, s);
    }

    public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s, final SSLEngine sslEngine) throws CertificateException {
        delegate.checkClientTrusted(x509Certificates, s);
    }

    public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s, final SSLEngine sslEngine) throws CertificateException {
        delegate.checkServerTrusted(x509Certificates, s);
    }

    public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
        delegate.checkClientTrusted(x509Certificates, s);
    }

    public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
        delegate.checkServerTrusted(x509Certificates, s);
    }

    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
