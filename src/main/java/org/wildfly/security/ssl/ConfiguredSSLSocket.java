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
public final class ConfiguredSSLSocket extends AbstractDelegatingSSLSocket {

    public ConfiguredSSLSocket(final SSLSocket delegate) {
        super(delegate);
    }

    public void setEnabledCipherSuites(final String[] suites) {
        // ignored
    }

    public void setEnabledProtocols(final String[] protocols) {
        // ignored
    }

    public void setSSLParameters(final SSLParameters params) {
        final SSLParameters newParams = new SSLParameters(getEnabledCipherSuites(), getEnabledProtocols());
        newParams.setUseCipherSuitesOrder(params.getUseCipherSuitesOrder());
        newParams.setSNIMatchers(params.getSNIMatchers());
        newParams.setServerNames(params.getServerNames());
        newParams.setAlgorithmConstraints(params.getAlgorithmConstraints());
        newParams.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        newParams.setNeedClientAuth(params.getNeedClientAuth());
        newParams.setWantClientAuth(params.getWantClientAuth());
        super.setSSLParameters(newParams);
    }
}
