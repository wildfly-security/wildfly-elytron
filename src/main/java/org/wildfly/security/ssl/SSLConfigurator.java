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

/**
 * A configurator for SSL contexts and their produced objects.  Instances of this interface can be used to preconfigure,
 * limit, or modify the behavior of the SSL context.
 */
public interface SSLConfigurator {

    // configuration

    default void configure(SSLContext context, SSLServerSocket sslServerSocket) {
    }

    default void configure(SSLContext context, SSLSocket sslSocket) {
    }

    default void configure(SSLContext context, SSLEngine sslEngine) {
    }

    default void configure(SSLContext context) {
    }

    // SSLContext

    default SSLParameters getDefaultSSLParameters(SSLContext sslContext, SSLParameters original) {
        return original;
    }

    default SSLParameters getSupportedSSLParameters(SSLContext sslContext, SSLParameters original) {
        return original;
    }

    // SSLSocket/SSLEngine

    default void setWantClientAuth(SSLContext context, SSLSocket sslSocket, boolean value) {
        sslSocket.setWantClientAuth(value);
    }

    default void setWantClientAuth(SSLContext context, SSLEngine sslEngine, boolean value) {
        sslEngine.setWantClientAuth(value);
    }

    default void setWantClientAuth(SSLContext sslContext, SSLServerSocket sslServerSocket, boolean value) {
        sslServerSocket.setNeedClientAuth(value);
    }

    default void setNeedClientAuth(SSLContext context, SSLSocket sslSocket, boolean value) {
        sslSocket.setNeedClientAuth(value);
    }

    default void setNeedClientAuth(SSLContext context, SSLEngine sslEngine, boolean value) {
        sslEngine.setNeedClientAuth(value);
    }

    default void setNeedClientAuth(SSLContext sslContext, SSLServerSocket sslServerSocket, boolean value) {
        sslServerSocket.setNeedClientAuth(value);
    }

    default void setEnabledCipherSuites(SSLContext sslContext, SSLSocket sslSocket, String[] cipherSuites) {
        sslSocket.setEnabledCipherSuites(cipherSuites);
    }

    default void setEnabledCipherSuites(SSLContext sslContext, SSLEngine sslEngine, String[] cipherSuites) {
        sslEngine.setEnabledCipherSuites(cipherSuites);
    }

    default void setEnabledCipherSuites(SSLContext sslContext, SSLServerSocket sslServerSocket, String[] suites) {
        sslServerSocket.setEnabledCipherSuites(suites);
    }

    default void setEnabledProtocols(SSLContext sslContext, SSLSocket sslSocket, String[] protocols) {
        sslSocket.setEnabledProtocols(protocols);
    }

    default void setEnabledProtocols(SSLContext sslContext, SSLEngine sslEngine, String[] protocols) {
        sslEngine.setEnabledProtocols(protocols);
    }

    default void setEnabledProtocols(SSLContext sslContext, SSLServerSocket sslServerSocket, String[] protocols) {
        sslServerSocket.setEnabledProtocols(protocols);
    }

    default void setSSLParameters(SSLContext sslContext, SSLSocket sslSocket, SSLParameters parameters) {
        sslSocket.setSSLParameters(parameters);
    }

    default void setSSLParameters(SSLContext sslContext, SSLEngine sslEngine, SSLParameters parameters) {
        sslEngine.setSSLParameters(parameters);
    }

    default void setSSLParameters(SSLContext sslContext, SSLServerSocket sslServerSocket, SSLParameters parameters) {
        sslServerSocket.setSSLParameters(parameters);
    }

    default void setUseClientMode(SSLContext sslContext, SSLSocket sslSocket, boolean mode) {
        sslSocket.setUseClientMode(mode);
    }

    default void setUseClientMode(SSLContext sslContext, SSLEngine sslEngine, boolean mode) {
        sslEngine.setUseClientMode(mode);
    }

    default void setUseClientMode(SSLContext sslContext, SSLServerSocket sslServerSocket, boolean mode) {
        sslServerSocket.setUseClientMode(mode);
    }

    default void setEnableSessionCreation(SSLContext sslContext, SSLSocket sslSocket, boolean flag) {
        sslSocket.setEnableSessionCreation(flag);
    }

    default void setEnableSessionCreation(SSLContext sslContext, SSLEngine sslEngine, boolean flag) {
        sslEngine.setEnableSessionCreation(flag);
    }

    default void setEnableSessionCreation(SSLContext sslContext, SSLServerSocket sslServerSocket, boolean flag) {
        sslServerSocket.setEnableSessionCreation(flag);
    }

}
