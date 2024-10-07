/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import java.util.List;
import java.util.function.BiFunction;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;


final class JDKSpecific {

    /*
     * SSLEngine
     */

    static String getApplicationProtocol(SSLEngine sslEngine) {
        return sslEngine.getApplicationProtocol();
    }

    static String getHandshakeApplicationProtocol(SSLEngine sslEngine) {
        return sslEngine.getHandshakeApplicationProtocol();
    }

    static void setHandshakeApplicationProtocolSelector(SSLEngine sslEngine, BiFunction<SSLEngine, List<String>, String> selector) {
        sslEngine.setHandshakeApplicationProtocolSelector(selector);
    }

    static BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector(SSLEngine sslEngine) {
        return sslEngine.getHandshakeApplicationProtocolSelector();
    }

    /*
     * SSLParameters
     */

    static String[] getApplicationProtocols(SSLParameters parameters) {
        return parameters.getApplicationProtocols();
    }

    static void setApplicationProtocols(SSLParameters parameters, String[] protocols) {
        parameters.setApplicationProtocols(protocols);
    }

    /**
     * Copies SSLParameters' fields available in Java 9.
     *
     * @param original SSLParameters that should be applied to new instance
     * @return instance of SSLParameters with fields copied from original
     */
    static SSLParameters setSSLParameters(SSLParameters original) {
        SSLParameters params = new SSLParameters();
        params.setProtocols(original.getProtocols());
        params.setCipherSuites(original.getCipherSuites());
        params.setUseCipherSuitesOrder(original.getUseCipherSuitesOrder());
        params.setServerNames(original.getServerNames());
        params.setSNIMatchers(original.getSNIMatchers());
        params.setAlgorithmConstraints(original.getAlgorithmConstraints());
        params.setEndpointIdentificationAlgorithm(original.getEndpointIdentificationAlgorithm());
        if (original.getWantClientAuth()) {
            params.setWantClientAuth(original.getWantClientAuth());
        } else if (original.getNeedClientAuth()) {
            params.setNeedClientAuth(original.getNeedClientAuth());
        }
        // set java9 parameters
        params.setEnableRetransmissions(original.getEnableRetransmissions());
        params.setApplicationProtocols(original.getApplicationProtocols());
        params.setMaximumPacketSize(original.getMaximumPacketSize());
        return params;
    }

    /*
     * SSLSocket
     */

    static String getApplicationProtocol(SSLSocket socket) {
        return socket.getApplicationProtocol();
    }

    static String getHandshakeApplicationProtocol(SSLSocket socket) {
        return socket.getHandshakeApplicationProtocol();
    }

    static void setHandshakeApplicationProtocolSelector(SSLSocket socket, BiFunction<SSLSocket, List<String>, String> selector) {
        socket.setHandshakeApplicationProtocolSelector(selector);
    }

    static BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector(SSLSocket socket) {
        return socket.getHandshakeApplicationProtocolSelector();
    }
}
