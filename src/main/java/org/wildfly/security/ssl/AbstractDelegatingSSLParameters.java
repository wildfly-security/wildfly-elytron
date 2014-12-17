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

import java.security.AlgorithmConstraints;

import javax.net.ssl.SSLParameters;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class AbstractDelegatingSSLParameters extends SSLParameters {
    private final SSLParameters delegate;

    protected AbstractDelegatingSSLParameters(final SSLParameters delegate) {
        this.delegate = delegate;
    }

    public String[] getCipherSuites() {
        return delegate.getCipherSuites();
    }

    public void setCipherSuites(final String[] cipherSuites) {
        delegate.setCipherSuites(cipherSuites);
    }

    public String[] getProtocols() {
        return delegate.getProtocols();
    }

    public void setProtocols(final String[] protocols) {
        delegate.setProtocols(protocols);
    }

    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    public void setWantClientAuth(final boolean wantClientAuth) {
        delegate.setWantClientAuth(wantClientAuth);
    }

    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    public void setNeedClientAuth(final boolean needClientAuth) {
        delegate.setNeedClientAuth(needClientAuth);
    }

    /*===== since 1.7 =====*/

    public AlgorithmConstraints getAlgorithmConstraints() {
        return delegate.getAlgorithmConstraints();
    }

    public void setAlgorithmConstraints(final AlgorithmConstraints constraints) {
        delegate.setAlgorithmConstraints(constraints);
    }

    public String getEndpointIdentificationAlgorithm() {
        return delegate.getEndpointIdentificationAlgorithm();
    }

    public void setEndpointIdentificationAlgorithm(final String algorithm) {
        delegate.setEndpointIdentificationAlgorithm(algorithm);
    }

    /*==== 1.8 special ====*/

    protected void copyJdk8FinalParameters() {
        setServerNames(delegate.getServerNames());
        setSNIMatchers(delegate.getSNIMatchers());
        setUseCipherSuitesOrder(delegate.getUseCipherSuitesOrder());
    }
}
