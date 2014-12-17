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

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ConfiguredSSLServerSocketFactory extends AbstractDelegatingSSLServerSocketFactory {
    private final ConfiguredSSLContextSpi contextSpi;

    ConfiguredSSLServerSocketFactory(final SSLServerSocketFactory delegate, final ConfiguredSSLContextSpi contextSpi) {
        super(delegate);
        this.contextSpi = contextSpi;
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
        return original instanceof SSLServerSocket ? new ConfiguredSSLServerSocket((SSLServerSocket) original, contextSpi.getProtocolSelector(), contextSpi.getCipherSuiteSelector()) : original;
    }
}
