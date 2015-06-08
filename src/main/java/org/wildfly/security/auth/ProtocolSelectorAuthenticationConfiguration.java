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

package org.wildfly.security.auth;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

import org.wildfly.security.ssl.ProtocolSelector;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ProtocolSelectorAuthenticationConfiguration extends AuthenticationConfiguration {

    private final ProtocolSelector protocolSelector;

    ProtocolSelectorAuthenticationConfiguration(final AuthenticationConfiguration parent, final ProtocolSelector protocolSelector) {
        super(parent);
        this.protocolSelector = protocolSelector;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new ProtocolSelectorAuthenticationConfiguration(newParent, protocolSelector);
    }

    ProtocolSelector getProtocolSelector() {
        return protocolSelector;
    }

    void configureSslEngine(final SSLEngine sslEngine) {
        super.configureSslEngine(sslEngine);
        sslEngine.setEnabledProtocols(protocolSelector.evaluate(sslEngine.getSupportedProtocols()));
    }

    void configureSslSocket(final SSLSocket sslSocket) {
        super.configureSslSocket(sslSocket);
        sslSocket.setEnabledProtocols(protocolSelector.evaluate(sslSocket.getSupportedProtocols()));
    }
}
