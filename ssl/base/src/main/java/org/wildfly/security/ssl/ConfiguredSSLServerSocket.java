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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

/**
 * An SSL server socket which is pre-configured with a specific protocol and cipher suite selection.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ConfiguredSSLServerSocket extends AbstractDelegatingSSLServerSocket {

    private final SSLContext sslContext;
    private final SSLConfigurator sslConfigurator;

    ConfiguredSSLServerSocket(final SSLServerSocket delegate, final SSLContext sslContext, final SSLConfigurator sslConfigurator) throws IOException {
        super(delegate);
        this.sslContext = sslContext;
        this.sslConfigurator = sslConfigurator;
    }

    public void setEnabledCipherSuites(final String[] suites) {
        sslConfigurator.setEnabledCipherSuites(sslContext, getDelegate(), suites);
    }

    public void setEnabledProtocols(final String[] protocols) {
        sslConfigurator.setEnabledProtocols(sslContext, getDelegate(), protocols);
    }

    public void setSSLParameters(final SSLParameters params) {
        sslConfigurator.setSSLParameters(sslContext, getDelegate(), params);
    }

    public void setNeedClientAuth(final boolean need) {
        sslConfigurator.setNeedClientAuth(sslContext, getDelegate(), need);
    }

    public void setWantClientAuth(final boolean want) {
        sslConfigurator.setWantClientAuth(sslContext, getDelegate(), want);
    }

    public void setUseClientMode(final boolean clientMode) {
        sslConfigurator.setUseClientMode(sslContext, getDelegate(), clientMode);
    }

    public void setEnableSessionCreation(final boolean enabled) {
        sslConfigurator.setEnableSessionCreation(sslContext, getDelegate(), enabled);
    }
}
