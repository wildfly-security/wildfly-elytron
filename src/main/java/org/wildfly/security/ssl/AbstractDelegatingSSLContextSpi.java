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

package org.wildfly.security.ssl;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class AbstractDelegatingSSLContextSpi extends SSLContextSpi {
    private final SSLContext delegate;

    AbstractDelegatingSSLContextSpi(final SSLContext delegate) {
        this.delegate = delegate;
    }

    protected void engineInit(final KeyManager[] km, final TrustManager[] tm, final SecureRandom sr) throws KeyManagementException {
        delegate.init(km, tm, sr);
    }

    protected SSLSocketFactory engineGetSocketFactory() {
        return delegate.getSocketFactory();
    }

    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return delegate.getServerSocketFactory();
    }

    protected SSLEngine engineCreateSSLEngine() {
        return delegate.createSSLEngine();
    }

    protected SSLEngine engineCreateSSLEngine(final String host, final int port) {
        return delegate.createSSLEngine(host, port);
    }

    protected SSLSessionContext engineGetServerSessionContext() {
        return delegate.getServerSessionContext();
    }

    protected SSLSessionContext engineGetClientSessionContext() {
        return delegate.getClientSessionContext();
    }

    protected SSLParameters engineGetDefaultSSLParameters() {
        return delegate.getDefaultSSLParameters();
    }

    protected SSLParameters engineGetSupportedSSLParameters() {
        return delegate.getSupportedSSLParameters();
    }

    public SSLContext getDelegate() {
        return delegate;
    }
}
