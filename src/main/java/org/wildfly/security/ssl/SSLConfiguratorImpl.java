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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;

final class SSLConfiguratorImpl implements SSLConfigurator {

    private final ProtocolSelector protocolSelector;
    private final CipherSuiteSelector cipherSuiteSelector;
    private final boolean wantClientAuth;
    private final boolean needClientAuth;
    private final boolean useCipherSuitesOrder;
    private final boolean clientMode;

    /**
     * Construct a new instance in server mode.
     *
     * @param protocolSelector the protocol selector (must not be {@code null})
     * @param cipherSuiteSelector the cipher suite selector (must not be {@code null})
     * @param wantClientAuth {@code true} to request client authentication
     * @param needClientAuth {@code true} to require client authentication
     */
    SSLConfiguratorImpl(final ProtocolSelector protocolSelector, final CipherSuiteSelector cipherSuiteSelector, final boolean wantClientAuth, final boolean needClientAuth, final boolean useCipherSuitesOrder) {
        this.protocolSelector = protocolSelector;
        this.cipherSuiteSelector = cipherSuiteSelector;
        this.useCipherSuitesOrder = useCipherSuitesOrder;
        this.wantClientAuth = wantClientAuth;
        this.needClientAuth = needClientAuth;
        clientMode = false;
    }

    /**
     * Construct a new instance in client mode.
     *
     * @param protocolSelector the protocol selector (must not be {@code null})
     * @param cipherSuiteSelector the cipher suite selector (must not be {@code null})
     */
    SSLConfiguratorImpl(final ProtocolSelector protocolSelector, final CipherSuiteSelector cipherSuiteSelector, final boolean useCipherSuitesOrder) {
        this.protocolSelector = protocolSelector;
        this.cipherSuiteSelector = cipherSuiteSelector;
        this.useCipherSuitesOrder = useCipherSuitesOrder;
        this.wantClientAuth = false;
        this.needClientAuth = false;
        clientMode = true;
    }

    void configure(SSLParameters params, String[] supportedProtocols, String[] supportedCipherSuites) {
        Assert.checkNotNullParam("supportedProtocols", supportedProtocols);
        Assert.checkNotNullParam("supportedCipherSuites", supportedCipherSuites);
        params.setProtocols(protocolSelector.evaluate(supportedProtocols));
        params.setCipherSuites(cipherSuiteSelector.evaluate(supportedCipherSuites));
        params.setUseCipherSuitesOrder(useCipherSuitesOrder);
        params.setWantClientAuth(wantClientAuth); // unsets need
        if (needClientAuth) params.setNeedClientAuth(needClientAuth); // unsets want
    }

    public void configure(final SSLContext context, final SSLServerSocket sslServerSocket) {
        sslServerSocket.setUseClientMode(clientMode);
        final SSLParameters sslParameters = sslServerSocket.getSSLParameters();
        configure(sslParameters, sslServerSocket.getSupportedProtocols(), sslServerSocket.getSupportedCipherSuites());
        sslServerSocket.setSSLParameters(sslParameters);
    }

    public void configure(final SSLContext context, final SSLSocket sslSocket) {
        sslSocket.setUseClientMode(clientMode);
        final SSLParameters sslParameters = sslSocket.getSSLParameters();
        configure(sslParameters, sslSocket.getSupportedProtocols(), sslSocket.getSupportedCipherSuites());
        sslSocket.setSSLParameters(sslParameters);
    }

    public void configure(final SSLContext context, final SSLEngine sslEngine) {
        sslEngine.setUseClientMode(clientMode);
        final SSLParameters sslParameters = sslEngine.getSSLParameters();
        configure(sslParameters, sslEngine.getSupportedProtocols(), sslEngine.getSupportedCipherSuites());
        sslEngine.setSSLParameters(sslParameters);
    }

    public SSLParameters getDefaultSSLParameters(final SSLContext sslContext, final SSLParameters original) {
        final SSLParameters supportedSSLParameters = sslContext.getSupportedSSLParameters();
        configure(original, supportedSSLParameters.getProtocols(), supportedSSLParameters.getCipherSuites());
        return original;
    }

    public SSLParameters getSupportedSSLParameters(final SSLContext sslContext, final SSLParameters original) {
        return getDefaultSSLParameters(sslContext, original);
    }

    public void setWantClientAuth(final SSLContext context, final SSLSocket sslSocket, final boolean value) {
        if (value) sslSocket.setWantClientAuth(value);
    }

    public void setWantClientAuth(final SSLContext context, final SSLEngine sslEngine, final boolean value) {
        if (value) sslEngine.setWantClientAuth(value);
    }

    public void setWantClientAuth(final SSLContext sslContext, final SSLServerSocket sslServerSocket, final boolean value) {
        if (value) sslServerSocket.setWantClientAuth(value);
    }

    public void setNeedClientAuth(final SSLContext context, final SSLSocket sslSocket, final boolean value) {
        if (value) sslSocket.setNeedClientAuth(value);
    }

    public void setNeedClientAuth(final SSLContext context, final SSLEngine sslEngine, final boolean value) {
        if (value) sslEngine.setNeedClientAuth(value);
    }

    public void setNeedClientAuth(final SSLContext sslContext, final SSLServerSocket sslServerSocket, final boolean value) {
        if (value) sslServerSocket.setNeedClientAuth(value);
    }

    public void setEnabledCipherSuites(final SSLContext sslContext, final SSLSocket sslSocket, final String[] cipherSuites) {
        // ignored
    }

    public void setEnabledCipherSuites(final SSLContext sslContext, final SSLEngine sslEngine, final String[] cipherSuites) {
        // ignored
    }

    public void setEnabledCipherSuites(final SSLContext sslContext, final SSLServerSocket sslServerSocket, final String[] suites) {
        // ignored
    }

    public void setEnabledProtocols(final SSLContext sslContext, final SSLSocket sslSocket, final String[] protocols) {
        // ignored
    }

    public void setEnabledProtocols(final SSLContext sslContext, final SSLEngine sslEngine, final String[] protocols) {
        // ignored
    }

    public void setEnabledProtocols(final SSLContext sslContext, final SSLServerSocket sslServerSocket, final String[] protocols) {
        // ignored
    }

    private SSLParameters redefine(SSLParameters original, String[] supportedCipherSuites, String[] supportedProtocols) {
        final SSLParameters params = new SSLParameters();
        configure(params, protocolSelector.evaluate(supportedProtocols), cipherSuiteSelector.evaluate(supportedCipherSuites));
        // copy all other parameters over
        params.setServerNames(original.getServerNames());
        params.setSNIMatchers(original.getSNIMatchers());
        params.setAlgorithmConstraints(original.getAlgorithmConstraints());
        params.setEndpointIdentificationAlgorithm(original.getEndpointIdentificationAlgorithm());
        return params;
    }

    public void setSSLParameters(final SSLContext sslContext, final SSLSocket sslSocket, final SSLParameters parameters) {
        sslSocket.setSSLParameters(redefine(parameters, sslSocket.getSupportedCipherSuites(), sslSocket.getSupportedProtocols()));
    }

    public void setSSLParameters(final SSLContext sslContext, final SSLEngine sslEngine, final SSLParameters parameters) {
        sslEngine.setSSLParameters(redefine(parameters, sslEngine.getSupportedCipherSuites(), sslEngine.getSupportedProtocols()));
    }

    public void setSSLParameters(final SSLContext sslContext, final SSLServerSocket sslServerSocket, final SSLParameters parameters) {
        sslServerSocket.setSSLParameters(redefine(parameters, sslServerSocket.getSupportedCipherSuites(), sslServerSocket.getSupportedProtocols()));
    }

    public void setUseClientMode(final SSLContext sslContext, final SSLSocket sslSocket, final boolean mode) {
        if (mode != clientMode) {
            throw ElytronMessages.log.invalidClientMode(clientMode, mode);
        }
        // ignored
    }

    public void setUseClientMode(final SSLContext sslContext, final SSLEngine sslEngine, final boolean mode) {
        if (mode != clientMode) {
            throw ElytronMessages.log.invalidClientMode(clientMode, mode);
        }
        // ignored
    }

    public void setUseClientMode(final SSLContext sslContext, final SSLServerSocket sslServerSocket, final boolean mode) {
        if (mode != clientMode) {
            throw ElytronMessages.log.invalidClientMode(clientMode, mode);
        }
        // ignored
    }
}
