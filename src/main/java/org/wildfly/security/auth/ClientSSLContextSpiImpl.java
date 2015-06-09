/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.wildfly.security.ssl.AbstractDelegatingSSLContextSpi;
import org.wildfly.security.ssl.AbstractDelegatingSSLEngine;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ClientSSLContextSpiImpl extends AbstractDelegatingSSLContextSpi {

    private final AuthenticationConfiguration configuration;

    ClientSSLContextSpiImpl(final SSLContext delegate, final AuthenticationConfiguration configuration) {
        super(delegate);
        this.configuration = configuration;
    }

    protected void engineInit(final KeyManager[] km, final TrustManager[] tm, final SecureRandom sr) throws KeyManagementException {
        // already initialized
        throw new IllegalStateException();
    }

    protected SSLSocketFactory engineGetSocketFactory() {
        return configuration.createClientSslSocketFactory(getDelegate().getSocketFactory());
    }

    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        throw new UnsupportedOperationException();
    }

    protected SSLEngine engineCreateSSLEngine() {
        final SSLEngine sslEngine = getDelegate().createSSLEngine();
        configuration.configureSslEngine(sslEngine);
        return wrapSSLEngine(sslEngine);
    }

    protected SSLEngine engineCreateSSLEngine(final String host, final int port) {
        final SSLEngine sslEngine = getDelegate().createSSLEngine(host, port);
        configuration.configureSslEngine(sslEngine);
        return wrapSSLEngine(sslEngine);
    }

    private AbstractDelegatingSSLEngine wrapSSLEngine(final SSLEngine sslEngine) {
        return new AbstractDelegatingSSLEngine(sslEngine) {
            public void setSSLParameters(final SSLParameters params) {
                final SSLParameters newParameters = sslEngine.getSSLParameters();
                newParameters.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
                newParameters.setAlgorithmConstraints(params.getAlgorithmConstraints());
                newParameters.setServerNames(params.getServerNames());
                super.setSSLParameters(newParameters);
            }

            public void setUseClientMode(final boolean mode) {
                if (! mode) throw new UnsupportedOperationException();
            }

            public void setEnabledCipherSuites(final String[] suites) {
                // ignored
            }

            public void setEnabledProtocols(final String[] protocols) {
                // ignored
            }
        };
    }
}
