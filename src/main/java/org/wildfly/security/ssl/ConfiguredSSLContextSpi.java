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

    private volatile ProtocolSelector protocolSelector;
    private volatile CipherSuiteSelector cipherSuiteSelector;

    ConfiguredSSLContextSpi(final SSLContext delegate, final ProtocolSelector protocolSelector, final CipherSuiteSelector cipherSuiteSelector) {
        super(delegate);
        if (protocolSelector == null) {
            throw new IllegalArgumentException("protocolSelector is null");
        }
        if (cipherSuiteSelector == null) {
            throw new IllegalArgumentException("cipherSuiteSelector is null");
        }
        this.protocolSelector = protocolSelector;
        this.cipherSuiteSelector = cipherSuiteSelector;
    }

    protected SSLSocketFactory engineGetSocketFactory() {
        return new ConfiguredSSLSocketFactory(super.engineGetSocketFactory(), this);
    }

    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return super.engineGetServerSocketFactory();
    }

    protected SSLEngine engineCreateSSLEngine() {
        return new ConfiguredSSLEngine(super.engineCreateSSLEngine(), protocolSelector, cipherSuiteSelector);
    }

    protected SSLEngine engineCreateSSLEngine(final String host, final int port) {
        return new ConfiguredSSLEngine(super.engineCreateSSLEngine(host, port), protocolSelector, cipherSuiteSelector);
    }

    protected SSLParameters engineGetDefaultSSLParameters() {
        // these will always be identical
        return engineGetSupportedSSLParameters();
    }

    protected SSLParameters engineGetSupportedSSLParameters() {
        final SSLParameters parameters = super.engineGetSupportedSSLParameters();
        parameters.setCipherSuites(cipherSuiteSelector.evaluate(parameters.getCipherSuites()));
        parameters.setProtocols(protocolSelector.evaluate(parameters.getProtocols()));
        return parameters;
    }

    ProtocolSelector getProtocolSelector() {
        return protocolSelector;
    }

    void setProtocolSelector(final ProtocolSelector protocolSelector) {
        if (protocolSelector == null) {
            throw new IllegalArgumentException("protocolSelector is null");
        }
        this.protocolSelector = protocolSelector;
    }

    CipherSuiteSelector getCipherSuiteSelector() {
        return cipherSuiteSelector;
    }

    void setCipherSuiteSelector(final CipherSuiteSelector cipherSuiteSelector) {
        if (cipherSuiteSelector == null) {
            throw new IllegalArgumentException("cipherSuiteSelector is null");
        }
        this.cipherSuiteSelector = cipherSuiteSelector;
    }
}
