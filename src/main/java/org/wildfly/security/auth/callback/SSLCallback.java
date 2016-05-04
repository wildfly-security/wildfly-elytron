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

package org.wildfly.security.auth.callback;

import java.io.Serializable;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * A callback which provides information to the callback handler about the established SSL/TLS security layer involved
 * in an authentication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = 7854221380587494535L;

    /**
     * @serial The SSL context.
     */
    private final SSLContext sslContext;
    /**
     * @serial The SSL engine, if any.
     */
    private final SSLEngine sslEngine;
    /**
     * @serial The SSL socket, if any.
     */
    private final SSLSocket sslSocket;

    /**
     * Construct a new instance.
     *
     * @param sslContext the SSL context used
     * @param sslSocket the SSL socket
     */
    public SSLCallback(final SSLContext sslContext, final SSLSocket sslSocket) {
        this.sslContext = sslContext;
        this.sslSocket = sslSocket;
        sslEngine = null;
    }

    /**
     * Construct a new instance.
     *
     * @param sslContext the SSL context used
     * @param sslEngine the SSL engine of the connection
     */
    public SSLCallback(final SSLContext sslContext, final SSLEngine sslEngine) {
        this.sslContext = sslContext;
        this.sslEngine = sslEngine;
        sslSocket = null;
    }

    /**
     * Get the SSL context used.
     *
     * @return the SSL context used
     */
    public SSLContext getSslContext() {
        return sslContext;
    }

    /**
     * Get the SSL session in force.
     *
     * @return the SSL session in force
     */
    public SSLSession getSslSession() {
        return sslEngine != null ? sslEngine.getSession() : sslSocket.getSession();
    }

    /**
     * Get the SSL parameters in use.
     *
     * @return the SSL parameters in use
     */
    public SSLParameters getSslParameters() {
        return sslEngine != null ? sslEngine.getSSLParameters() : sslSocket.getSSLParameters();
    }

    /**
     * Determine whether the SSL connection is in "client mode".
     *
     * @return {@code true} for client mode, {@code false} for server mode
     */
    public boolean isClientMode() {
        return sslEngine != null ? sslEngine.getUseClientMode() : sslSocket.getUseClientMode();
    }

    /**
     * Determine whether client authentication was requested.
     *
     * @return {@code true} if client authentication was requested, {@code false} otherwise
     */
    public boolean isClientAuthWanted() {
        return sslEngine != null ? sslEngine.getWantClientAuth() : sslSocket.getWantClientAuth();
    }

    /**
     * Determine whether client authentication was required.
     *
     * @return {@code true} if client authentication was required, {@code false} otherwise
     */
    public boolean isClientAuthNeeded() {
        return sslEngine != null ? sslEngine.getNeedClientAuth() : sslSocket.getNeedClientAuth();
    }

    /**
     * Determine whether session creation is enabled for this connection.
     *
     * @return {@code true} if session creation is enabled, {@code false} otherwise
     */
    public boolean isSessionCreationEnabled() {
        return sslEngine != null ? sslEngine.getEnableSessionCreation() : sslSocket.getEnableSessionCreation();
    }
}
