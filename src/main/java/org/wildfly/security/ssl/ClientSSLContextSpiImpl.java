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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.wildfly.security.auth.AuthenticationContext;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ClientSSLContextSpiImpl extends AbstractDelegatingSSLContextSpi {

    ClientSSLContextSpiImpl(final SSLContext delegate) {
        super(delegate);
    }

    protected void engineInit(final KeyManager[] km, final TrustManager[] tm, final SecureRandom sr) throws KeyManagementException {
        // already initialized
        throw new IllegalStateException();
    }

    protected SSLSocketFactory engineGetSocketFactory() {
        return new AbstractDelegatingSSLSocketFactory(super.engineGetSocketFactory()) {
            private SSLSocket wrap(Socket s) {
                final SSLSocket sslSocket = (SSLSocket) s;
                final AuthenticationContext context = AuthenticationContext.captureCurrent();
                return new AbstractDelegatingSSLSocket(sslSocket) {
                    public void connect(final SocketAddress endpoint) throws IOException {
                        connect(endpoint, 0);
                    }

                    public void connect(final SocketAddress endpoint, final int timeout) throws IOException {
                        super.connect(endpoint, timeout);
                    }

                    public void setEnabledCipherSuites(final String[] suites) {
                        // ignored
                    }

                    public void setEnabledProtocols(final String[] protocols) {
                        // ignored
                    }

                    public void setWantClientAuth(final boolean want) {
                        // ignored
                    }

                    public void setSSLParameters(final SSLParameters params) {
                        // ignored
                    }
                };
            }

            public Socket createSocket(final Socket s, final String host, final int port, final boolean autoClose) throws IOException {
                return super.createSocket(s, host, port, autoClose);
            }

            public Socket createSocket() throws IOException {
                return super.createSocket();
            }

            public Socket createSocket(final String host, final int port) throws IOException {
                return super.createSocket(host, port);
            }

            public Socket createSocket(final String host, final int port, final InetAddress localHost, final int localPort) throws IOException {
                return super.createSocket(host, port, localHost, localPort);
            }

            public Socket createSocket(final InetAddress host, final int port) throws IOException {
                return super.createSocket(host, port);
            }

            public Socket createSocket(final InetAddress address, final int port, final InetAddress localAddress, final int localPort) throws IOException {
                return super.createSocket(address, port, localAddress, localPort);
            }

//            public Socket createSocket(final Socket socket, final InputStream inputStream, final boolean autoClose) throws IOException {
//                return super.createSocket(socket, inputStream, autoClose);
//            }
        };
    }

    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return null;
    }

    protected SSLEngine engineCreateSSLEngine() {
        return null;
    }

    protected SSLEngine engineCreateSSLEngine(final String host, final int port) {
        return null;
    }

    protected SSLSessionContext engineGetServerSessionContext() {
        return null;
    }

    protected SSLSessionContext engineGetClientSessionContext() {
        return null;
    }
}
