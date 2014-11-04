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

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * An SSL socket which is pre-configured with a specific protocol and cipher suite selection.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ConfiguredSSLSocket extends AbstractDelegatingSSLSocket {

    private final ProtocolSelector protocolSelector;
    private final CipherSuiteSelector cipherSuiteSelector;

    ConfiguredSSLSocket(final SSLSocket delegate, final ProtocolSelector protocolSelector, final CipherSuiteSelector cipherSuiteSelector) {
        super(delegate);
        this.protocolSelector = protocolSelector;
        this.cipherSuiteSelector = cipherSuiteSelector;
        delegate.setEnabledProtocols(protocolSelector.evaluate(delegate.getSupportedProtocols()));
        delegate.setEnabledCipherSuites(cipherSuiteSelector.evaluate(delegate.getSupportedCipherSuites()));
    }

    public void setEnabledCipherSuites(final String[] suites) {
        // ignored
    }

    public void setEnabledProtocols(final String[] protocols) {
        // ignored
    }

    public void setSSLParameters(final SSLParameters params) {
        super.setSSLParameters(params);
        // re-set the protocols and cipher suites
        super.setEnabledProtocols(protocolSelector.evaluate(super.getSupportedProtocols()));
        super.setEnabledCipherSuites(cipherSuiteSelector.evaluate(super.getSupportedCipherSuites()));
    }
}
