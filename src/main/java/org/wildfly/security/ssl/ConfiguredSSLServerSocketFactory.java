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
import java.net.ServerSocket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ConfiguredSSLServerSocketFactory extends AbstractDelegatingSSLServerSocketFactory {
    private final SSLContext sslContext;
    private final SSLConfigurator sslConfigurator;

    ConfiguredSSLServerSocketFactory(final SSLServerSocketFactory delegate, final SSLContext sslContext, final SSLConfigurator sslConfigurator) {
        super(delegate);
        this.sslContext = sslContext;
        this.sslConfigurator = sslConfigurator;
    }

    public ServerSocket createServerSocket() throws IOException {
        return wrap(super.createServerSocket());
    }

    public ServerSocket createServerSocket(final int port) throws IOException {
        return wrap(super.createServerSocket(port));
    }

    public ServerSocket createServerSocket(final int port, final int backlog) throws IOException {
        return wrap(super.createServerSocket(port, backlog));
    }

    public ServerSocket createServerSocket(final int port, final int backlog, final InetAddress ifAddress) throws IOException {
        return wrap(super.createServerSocket(port, backlog, ifAddress));
    }

    private ServerSocket wrap(ServerSocket original) throws IOException {
        if (original instanceof SSLServerSocket) {
            final SSLServerSocket sslServerSocket = (SSLServerSocket) original;
            final SSLContext sslContext = this.sslContext;
            final SSLConfigurator sslConfigurator = this.sslConfigurator;
            sslConfigurator.configure(sslContext, sslServerSocket);
            return new ConfiguredSSLServerSocket(sslServerSocket, sslContext, sslConfigurator);
        } else {
            return original;
        }
    }
}
