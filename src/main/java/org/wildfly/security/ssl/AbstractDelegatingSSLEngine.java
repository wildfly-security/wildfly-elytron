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

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class AbstractDelegatingSSLEngine extends SSLEngine {
    private final SSLEngine delegate;

    protected AbstractDelegatingSSLEngine(final SSLEngine delegate) {
        this.delegate = delegate;
    }

    public String getPeerHost() {
        return delegate.getPeerHost();
    }

    public int getPeerPort() {
        return delegate.getPeerPort();
    }

    public SSLEngineResult wrap(final ByteBuffer src, final ByteBuffer dst) throws SSLException {
        return delegate.wrap(src, dst);
    }

    public SSLEngineResult wrap(final ByteBuffer[] srcs, final int offset, final int length, final ByteBuffer dst) throws SSLException {
        return delegate.wrap(srcs, offset, length, dst);
    }

    public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer dst) throws SSLException {
        return delegate.unwrap(src, dst);
    }

    public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts, final int offset, final int length) throws SSLException {
        return delegate.unwrap(src, dsts, offset, length);
    }

    public Runnable getDelegatedTask() {
        return delegate.getDelegatedTask();
    }

    public void closeInbound() throws SSLException {
        delegate.closeInbound();
    }

    public boolean isInboundDone() {
        return delegate.isInboundDone();
    }

    public void closeOutbound() {
        delegate.closeOutbound();
    }

    public boolean isOutboundDone() {
        return delegate.isOutboundDone();
    }

    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    public void setEnabledCipherSuites(final String[] suites) {
        delegate.setEnabledCipherSuites(suites);
    }

    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }

    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    public void setEnabledProtocols(final String[] protocols) {
        delegate.setEnabledProtocols(protocols);
    }

    public SSLSession getSession() {
        return delegate.getSession();
    }

    public SSLSession getHandshakeSession() {
        return delegate.getHandshakeSession();
    }

    public void beginHandshake() throws SSLException {
        delegate.beginHandshake();
    }

    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return delegate.getHandshakeStatus();
    }

    public void setUseClientMode(final boolean mode) {
        delegate.setUseClientMode(mode);
    }

    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    public void setNeedClientAuth(final boolean need) {
        delegate.setNeedClientAuth(need);
    }

    public boolean getNeedClientAuth() {
        return delegate.getNeedClientAuth();
    }

    public void setWantClientAuth(final boolean want) {
        delegate.setWantClientAuth(want);
    }

    public boolean getWantClientAuth() {
        return delegate.getWantClientAuth();
    }

    public void setEnableSessionCreation(final boolean flag) {
        delegate.setEnableSessionCreation(flag);
    }

    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }

    public SSLParameters getSSLParameters() {
        return delegate.getSSLParameters();
    }

    public void setSSLParameters(final SSLParameters params) {
        delegate.setSSLParameters(params);
    }
}
