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
        throw new UnsupportedOperationException();
    }

    static String getHandshakeApplicationProtocol(SSLEngine sslEngine) {
        throw new UnsupportedOperationException();
    }

    static void setHandshakeApplicationProtocolSelector(SSLEngine sslEngine, BiFunction<SSLEngine, List<String>, String> selector) {
        throw new UnsupportedOperationException();
    }

    static BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector(SSLEngine sslEngine) {
        throw new UnsupportedOperationException();
    }

    /*
     * SSLParameters
     */

    static String[] getApplicationProtocols(SSLParameters parameters) {
        throw new UnsupportedOperationException();
    }

    static void setApplicationProtocols(SSLParameters parameters, String[] protocols) {
        throw new UnsupportedOperationException();
    }

    /**
     * Copies SSLParameters' fields available in java 8.
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
        return params;
    }

    /*
     * SSLSocket
     */

    static String getApplicationProtocol(SSLSocket socket) {
        throw new UnsupportedOperationException();
    }

    static String getHandshakeApplicationProtocol(SSLSocket socket) {
        throw new UnsupportedOperationException();
    }

    static void setHandshakeApplicationProtocolSelector(SSLSocket socket, BiFunction<SSLSocket, List<String>, String> selector) {
        throw new UnsupportedOperationException();
    }

    static BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector(SSLSocket socket) {
        throw new UnsupportedOperationException();
    }

}
