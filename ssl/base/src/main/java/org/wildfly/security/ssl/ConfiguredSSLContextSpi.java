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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ConfiguredSSLContextSpi extends AbstractDelegatingSSLContextSpi {

    private final SSLConfigurator sslConfigurator;
    private final boolean wrap;

    ConfiguredSSLContextSpi(final SSLContext delegate, final SSLConfigurator sslConfigurator, final boolean wrap) {
        super(delegate);
        this.sslConfigurator = sslConfigurator;
        this.wrap = wrap;
    }

    protected SSLSocketFactory engineGetSocketFactory() {
        return new ConfiguredSSLSocketFactory(super.engineGetSocketFactory(), getDelegate(), sslConfigurator, wrap);
    }

    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return new ConfiguredSSLServerSocketFactory(super.engineGetServerSocketFactory(), getDelegate(), sslConfigurator, wrap);
    }

    protected SSLEngine engineCreateSSLEngine() {
        final SSLEngine sslEngine = super.engineCreateSSLEngine();
        final SSLConfigurator sslConfigurator = this.sslConfigurator;
        sslConfigurator.configure(getDelegate(), sslEngine);
        return wrap ? new ConfiguredSSLEngine(sslEngine, getDelegate(), sslConfigurator) : sslEngine;
    }

    protected SSLEngine engineCreateSSLEngine(final String host, final int port) {
        final SSLEngine sslEngine = super.engineCreateSSLEngine(host, port);
        final SSLConfigurator sslConfigurator = this.sslConfigurator;
        sslConfigurator.configure(getDelegate(), sslEngine);
        return wrap ? new ConfiguredSSLEngine(sslEngine, getDelegate(), sslConfigurator) : sslEngine;
    }

    protected SSLParameters engineGetDefaultSSLParameters() {
        final SSLContext delegate = getDelegate();
        return sslConfigurator.getDefaultSSLParameters(delegate, delegate.getDefaultSSLParameters());
    }

    protected SSLParameters engineGetSupportedSSLParameters() {
        final SSLContext delegate = getDelegate();
        return sslConfigurator.getSupportedSSLParameters(delegate, delegate.getSupportedSSLParameters());
    }
}
