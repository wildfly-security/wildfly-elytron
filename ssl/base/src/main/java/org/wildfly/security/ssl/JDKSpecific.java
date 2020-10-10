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

import static org.wildfly.security.ssl.BaseElytronMessages.tls;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.function.BiFunction;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

final class JDKSpecific {

    // SSLEngine Methods

    private static final Method SSLENGINE_GET_APPLICATION_PROTOCOL = getMethodOrNull(SSLEngine.class, "getApplicationProtocol");
    private static final Method SSLENGINE_GET_HANDSHAKE_APPLICATION_PROTOCOL = getMethodOrNull(SSLEngine.class, "getHandshakeApplicationProtocol");
    private static final Method SSLENGINE_SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR = getMethodOrNull(SSLEngine.class, "setHandshakeApplicationProtocolSelector", BiFunction.class);
    private static final Method SSLENGINE_GET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR = getMethodOrNull(SSLEngine.class, "getHandshakeApplicationProtocolSelector");

    // SSLParameters Methods

    private static final Method SSLPARAMETERS_GET_APPLICATION_PROTOCOLS = getMethodOrNull(SSLParameters.class, "getApplicationProtocols");
    private static final Method SSLPARAMETERS_SET_APPLICATION_PROTOCOLS = getMethodOrNull(SSLParameters.class, "setApplicationProtocols", String[].class);

    // SSLSocket Methods

    private static final Method SSLSOCKET_GET_APPLICATION_PROTOCOL = getMethodOrNull(SSLSocket.class, "getApplicationProtocol");
    private static final Method SSLSOCKET_GET_HANDSHAKE_APPLICATION_PROTOCOL = getMethodOrNull(SSLSocket.class, "getHandshakeApplicationProtocol");
    private static final Method SSLSOCKET_SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR = getMethodOrNull(SSLSocket.class, "setHandshakeApplicationProtocolSelector", BiFunction.class);
    private static final Method SSLSOCKET_GET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR = getMethodOrNull(SSLSocket.class, "getHandshakeApplicationProtocolSelector");

    private static Method getMethodOrNull(Class clazz, String methodName, Class... parameterTypes) {
        try {
        return clazz.getMethod(methodName, parameterTypes);
        } catch (Exception e) {
            if (tls.isTraceEnabled()) {
                tls.tracef(e, "Unable to getMethod %s on class %s", methodName, clazz.getName());
            } else if (tls.isDebugEnabled()) {
                tls.debugf("Unable to getMethod %s on class %s", methodName, clazz.getName());
            }

            return null;
        }
    }

    /*
     * SSLEngine
     */

    static String getApplicationProtocol(SSLEngine sslEngine) {
        if (SSLENGINE_GET_APPLICATION_PROTOCOL != null) {
            try {
                return (String) SSLENGINE_GET_APPLICATION_PROTOCOL.invoke(sslEngine);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

    static String getHandshakeApplicationProtocol(SSLEngine sslEngine) {
        if (SSLENGINE_GET_HANDSHAKE_APPLICATION_PROTOCOL != null) {
            try {
                return (String) SSLENGINE_GET_HANDSHAKE_APPLICATION_PROTOCOL.invoke(sslEngine);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

    static void setHandshakeApplicationProtocolSelector(SSLEngine sslEngine, BiFunction<SSLEngine, List<String>, String> selector) {
        if (SSLENGINE_SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR != null) {
            try {
                SSLENGINE_SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR.invoke(sslEngine, selector);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

    static BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector(SSLEngine sslEngine) {
        if (SSLENGINE_GET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR != null) {
            try {
                return (BiFunction<SSLEngine, List<String>, String>) SSLENGINE_GET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR.invoke(sslEngine);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

    /*
     * SSLParameters
     */

    static String[] getApplicationProtocols(SSLParameters parameters) {
        if (SSLPARAMETERS_GET_APPLICATION_PROTOCOLS != null) {
            try {
                return (String[]) SSLPARAMETERS_GET_APPLICATION_PROTOCOLS.invoke(parameters);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

    static void setApplicationProtocols(SSLParameters parameters, String[] protocols) {
        if (SSLPARAMETERS_SET_APPLICATION_PROTOCOLS != null) {
            try {
                SSLPARAMETERS_SET_APPLICATION_PROTOCOLS.invoke(parameters, (Object) protocols);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

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

        try {
            if (SSLPARAMETERS_GET_APPLICATION_PROTOCOLS != null && SSLPARAMETERS_SET_APPLICATION_PROTOCOLS != null) {
                setApplicationProtocols(params, getApplicationProtocols(original));
            }
        } catch (Exception ignored) {}

        return params;
    }

    /*
     * SSLSocket
     */

    static String getApplicationProtocol(SSLSocket socket) {
        if (SSLSOCKET_GET_APPLICATION_PROTOCOL != null) {
            try {
                return (String) SSLSOCKET_GET_APPLICATION_PROTOCOL.invoke(socket);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

    static String getHandshakeApplicationProtocol(SSLSocket socket) {
        if (SSLSOCKET_GET_HANDSHAKE_APPLICATION_PROTOCOL != null) {
            try {
                return (String) SSLSOCKET_GET_HANDSHAKE_APPLICATION_PROTOCOL.invoke(socket);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

    static void setHandshakeApplicationProtocolSelector(SSLSocket socket, BiFunction<SSLSocket, List<String>, String> selector) {
        if (SSLSOCKET_SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR != null) {
            try {
                SSLSOCKET_SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR.invoke(socket, selector);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

    static BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector(SSLSocket socket) {
        if (SSLSOCKET_GET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR != null) {
            try {
                return (BiFunction<SSLSocket, List<String>, String>) SSLSOCKET_GET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR.invoke(socket);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        }

        throw new UnsupportedOperationException();
    }

}
