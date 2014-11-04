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
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ConfiguredSSLSocketFactory extends AbstractDelegatingSSLSocketFactory {
    private final ConfiguredSSLContextSpi contextSpi;

    ConfiguredSSLSocketFactory(final SSLSocketFactory delegate, final ConfiguredSSLContextSpi contextSpi) {
        super(delegate);
        this.contextSpi = contextSpi;
    }

    public Socket createSocket(final Socket s, final String host, final int port, final boolean autoClose) throws IOException {
        return wrap(super.createSocket(s, host, port, autoClose));
    }

    public Socket createSocket() throws IOException {
        return wrap(super.createSocket());
    }

    public Socket createSocket(final String host, final int port) throws IOException {
        return wrap(super.createSocket(host, port));
    }

    public Socket createSocket(final String host, final int port, final InetAddress localHost, final int localPort) throws IOException {
        return wrap(super.createSocket(host, port, localHost, localPort));
    }

    public Socket createSocket(final InetAddress host, final int port) throws IOException {
        return wrap(super.createSocket(host, port));
    }

    public Socket createSocket(final InetAddress address, final int port, final InetAddress localAddress, final int localPort) throws IOException {
        return wrap(super.createSocket(address, port, localAddress, localPort));
    }

    public Socket createSocket(final Socket socket, final InputStream inputStream, final boolean autoClose) throws IOException {
        return wrap(super.createSocket(socket, inputStream, autoClose));
    }

    private Socket wrap(Socket orig) {
        return orig instanceof SSLSocket ? new ConfiguredSSLSocket((SSLSocket) orig, contextSpi.getProtocolSelector(), contextSpi.getCipherSuiteSelector()) : orig;
    }
}
