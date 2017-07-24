/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.ssl.TLSServerEndPointChannelBinding.*;

import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.wildfly.common.Assert;

/**
 * An SSL connection of some sort.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class SSLConnection {

    SSLConnection() {
    }

    /**
     * Get the SSL session associated with this connection.
     *
     * @return the SSL session associated with this connection, or {@code null} if there is none
     */
    public abstract SSLSession getSession();

    /**
     * Get the client-mode flag for this connection.
     *
     * @return the client-mode flag for this connection
     */
    public abstract boolean isClientMode();

    /**
     * Get the channel binding of the given type from this connection.  If the data is not present or the type is not
     * supported, {@code null} is returned.
     *
     * @return the channel binding of the given type from this connection, or {@code null} if it is not supported
     */
    public byte[] getChannelBinding(String bindingType) {
        // in JDK 10 and later (presumably), this method will be made abstract and the concrete impls will delegate directly to JSSE
        final boolean clientMode = isClientMode();
        switch (bindingType) {
            case TLS_SERVER_ENDPOINT: {
                final X509Certificate serverCert;
                final SSLSession session = getSession();
                if (session == null) {
                    return null;
                }
                if (clientMode) {
                    Certificate[] peerCertificates;
                    try {
                        peerCertificates = session.getPeerCertificates();
                    } catch (SSLPeerUnverifiedException e) {
                        peerCertificates = null;
                    }
                    serverCert = peerCertificates != null && peerCertificates.length > 0 ? (X509Certificate) peerCertificates[0] : null;
                } else {
                    final Certificate[] localCertificates = session.getLocalCertificates();
                    serverCert = localCertificates != null && localCertificates.length > 0 ? (X509Certificate) localCertificates[0] : null;
                }
                try {
                    return getChannelBindingData(serverCert);
                } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
                    return null;
                }
            }
            default: {
                return null;
            }
        }
    }

    /**
     * Create a {@code SSLConnection} for the given SSL engine.
     *
     * @param engine the SSL engine (must not be {@code null})
     * @return the SSL connection (not {@code null})
     */
    public static SSLConnection forEngine(SSLEngine engine) {
        Assert.checkNotNullParam("engine", engine);
        return new SSLConnection() {
            public SSLSession getSession() {
                return engine.getSession();
            }

            public boolean isClientMode() {
                return engine.getUseClientMode();
            }
        };
    }

    /**
     * Create a {@code SSLConnection} for the given SSL socket.
     *
     * @param socket the SSL socket (must not be {@code null})
     * @return the SSL connection (not {@code null})
     */
    public static SSLConnection forSocket(SSLSocket socket) {
        Assert.checkNotNullParam("socket", socket);
        return new SSLConnection() {
            public SSLSession getSession() {
                return socket.getSession();
            }

            public boolean isClientMode() {
                return socket.getUseClientMode();
            }
        };
    }

    /**
     * Create a {@code SSLConnection} for the given SSL socket.  Since no connection information will be
     * available in this case, not all channel binding modes will be supported.
     *
     * @param session the SSL session (must not be {@code null})
     * @param clientMode {@code true} if the session is client-side, {@code false} if it is server-side
     * @return the SSL connection (not {@code null})
     */
    public static SSLConnection forSession(SSLSession session, boolean clientMode) {
        Assert.checkNotNullParam("session", session);
        return new SSLConnection() {
            public SSLSession getSession() {
                return session;
            }

            public boolean isClientMode() {
                return clientMode;
            }
        };
    }
}
