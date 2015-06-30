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

package org.wildfly.security.ssl;

import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SNIServerSSLEngine extends SSLEngine {

    private final AtomicReference<SSLEngine> currentRef;

    SNIServerSSLEngine(final SNIServerSSLContextSelector selector) {
        currentRef = new AtomicReference<>(new InitialState(selector));
    }

    public SSLEngineResult wrap(final ByteBuffer[] srcs, final int offset, final int length, final ByteBuffer dst) throws SSLException {
        return currentRef.get().wrap(srcs, offset, length, dst);
    }

    public SSLEngineResult wrap(final ByteBuffer src, final ByteBuffer dst) throws SSLException {
        return currentRef.get().wrap(src, dst);
    }

    public SSLEngineResult wrap(final ByteBuffer[] srcs, final ByteBuffer dst) throws SSLException {
        return currentRef.get().wrap(srcs, dst);
    }

    public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts, final int offset, final int length) throws SSLException {
        return currentRef.get().unwrap(src, dsts, offset, length);
    }

    public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer dst) throws SSLException {
        return currentRef.get().unwrap(src, dst);
    }

    public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts) throws SSLException {
        return currentRef.get().unwrap(src, dsts);
    }

    public String getPeerHost() {
        return currentRef.get().getPeerHost();
    }

    public int getPeerPort() {
        return currentRef.get().getPeerPort();
    }

    public SSLSession getHandshakeSession() {
        return currentRef.get().getHandshakeSession();
    }

    public SSLParameters getSSLParameters() {
        return currentRef.get().getSSLParameters();
    }

    public void setSSLParameters(final SSLParameters params) {
        currentRef.get().setSSLParameters(params);
    }

    public Runnable getDelegatedTask() {
        return currentRef.get().getDelegatedTask();
    }

    public void closeInbound() throws SSLException {
        currentRef.get().closeInbound();
    }

    public boolean isInboundDone() {
        return currentRef.get().isInboundDone();
    }

    public void closeOutbound() {
        currentRef.get().closeOutbound();
    }

    public boolean isOutboundDone() {
        return currentRef.get().isOutboundDone();
    }

    public String[] getSupportedCipherSuites() {
        return currentRef.get().getSupportedCipherSuites();
    }

    public String[] getEnabledCipherSuites() {
        return currentRef.get().getEnabledCipherSuites();
    }

    public void setEnabledCipherSuites(final String[] cipherSuites) {
        currentRef.get().setEnabledCipherSuites(cipherSuites);
    }

    public String[] getSupportedProtocols() {
        return currentRef.get().getSupportedProtocols();
    }

    public String[] getEnabledProtocols() {
        return currentRef.get().getEnabledProtocols();
    }

    public void setEnabledProtocols(final String[] protocols) {
        currentRef.get().setEnabledProtocols(protocols);
    }

    public SSLSession getSession() {
        return currentRef.get().getSession();
    }

    public void beginHandshake() throws SSLException {
        currentRef.get().beginHandshake();
    }

    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return currentRef.get().getHandshakeStatus();
    }

    public void setUseClientMode(final boolean clientMode) {
        currentRef.get().setUseClientMode(clientMode);
    }

    public boolean getUseClientMode() {
        return currentRef.get().getUseClientMode();
    }

    public void setNeedClientAuth(final boolean clientAuth) {
         currentRef.get().setNeedClientAuth(clientAuth);
    }

    public boolean getNeedClientAuth() {
        return currentRef.get().getNeedClientAuth();
    }

    public void setWantClientAuth(final boolean want) {
        currentRef.get().setWantClientAuth(want);
    }

    public boolean getWantClientAuth() {
        return currentRef.get().getWantClientAuth();
    }

    public void setEnableSessionCreation(final boolean flag) {
        currentRef.get().setEnableSessionCreation(flag);
    }

    public boolean getEnableSessionCreation() {
        return currentRef.get().getEnableSessionCreation();
    }

    static final int FL_WANT_C_AUTH = 1 << 0;
    static final int FL_NEED_C_AUTH = 1 << 1;
    static final int FL_SESSION_CRE = 1 << 2;

    class InitialState extends SSLEngine {

        private final SNIServerSSLContextSelector selector;
        private final AtomicInteger flags = new AtomicInteger(FL_SESSION_CRE);

        InitialState(final SNIServerSSLContextSelector selector) {
            this.selector = selector;
        }

        public String getPeerHost() {
            return super.getPeerHost();
        }

        public int getPeerPort() {
            return super.getPeerPort();
        }

        public SSLSession getHandshakeSession() {
            return null;
        }

        public SSLEngineResult wrap(final ByteBuffer[] srcs, final int offset, final int length, final ByteBuffer dst) throws SSLException {
            return new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0);
        }

        public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts, final int offset, final int length) throws SSLException {
            SSLEngine next;
            final int mark = src.position();
            try {
                if (src.remaining() < SSLExplorer.RECORD_HEADER_SIZE) {
                    return new SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0);
                }
                final int requiredSize = SSLExplorer.getRequiredSize(src);
                if (src.remaining() < requiredSize) {
                    return new SSLEngineResult(SSLEngineResult.Status.BUFFER_UNDERFLOW, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0);
                }
                final SSLCapabilities capabilities = SSLExplorer.explore(src);
                final List<SNIServerName> serverNames = capabilities.getServerNames();
                SSLContext sslContext;
                final Iterator<SNIServerName> iterator = serverNames.iterator();
                if (! iterator.hasNext()) {
                    sslContext = selector.selectContext(null);
                } else do {
                    final SNIServerName serverName = iterator.next();
                    sslContext = selector.selectContext(serverName);
                    if (sslContext != null) {
                        break;
                    }
                } while (iterator.hasNext());
                if (sslContext == null) {
                    // no SSL context is available
                    throw ElytronMessages.log.noHostForSslConnection();
                }
                next = sslContext.createSSLEngine();
                next.setUseClientMode(false);
                final int flagsVal = flags.get();
                if ((flagsVal & FL_WANT_C_AUTH) != 0) {
                    next.setWantClientAuth(true);
                } else if ((flagsVal & FL_NEED_C_AUTH) != 0) {
                    next.setNeedClientAuth(true);
                }
                if ((flagsVal & FL_SESSION_CRE) != 0) {
                    next.setEnableSessionCreation(true);
                }
                currentRef.set(next);
            } finally {
                src.position(mark);
            }
            return next.unwrap(src, dsts, offset, length);
        }

        public Runnable getDelegatedTask() {
            return null;
        }

        public void closeInbound() throws SSLException {
            currentRef.set(CLOSED_STATE);
        }

        public boolean isInboundDone() {
            return false;
        }

        public void closeOutbound() {
            currentRef.set(CLOSED_STATE);
        }

        public boolean isOutboundDone() {
            return false;
        }

        public String[] getSupportedCipherSuites() {
            throw Assert.unsupported();
        }

        public String[] getEnabledCipherSuites() {
            throw Assert.unsupported();
        }

        public void setEnabledCipherSuites(final String[] suites) {
            throw Assert.unsupported();
        }

        public String[] getSupportedProtocols() {
            throw Assert.unsupported();
        }

        public String[] getEnabledProtocols() {
            throw Assert.unsupported();
        }

        public void setEnabledProtocols(final String[] protocols) {
            throw Assert.unsupported();
        }

        public SSLSession getSession() {
            return null;
        }

        public void beginHandshake() throws SSLException {
        }

        public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
            return SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }

        public void setUseClientMode(final boolean mode) {
            if (mode) throw Assert.unsupported();
        }

        public boolean getUseClientMode() {
            return false;
        }

        public void setNeedClientAuth(final boolean need) {
            final AtomicInteger flags = this.flags;
            int oldVal, newVal;
            do {
                oldVal = flags.get();
                if (((oldVal & FL_NEED_C_AUTH) != 0) == need) {
                    return;
                }
                newVal = oldVal & FL_SESSION_CRE | FL_NEED_C_AUTH;
            } while (! flags.compareAndSet(oldVal, newVal));
        }

        public boolean getNeedClientAuth() {
            return (flags.get() & FL_NEED_C_AUTH) != 0;
        }

        public void setWantClientAuth(final boolean want) {
            final AtomicInteger flags = this.flags;
            int oldVal, newVal;
            do {
                oldVal = flags.get();
                if (((oldVal & FL_WANT_C_AUTH) != 0) == want) {
                    return;
                }
                newVal = oldVal & FL_SESSION_CRE | FL_WANT_C_AUTH;
            } while (! flags.compareAndSet(oldVal, newVal));
        }

        public boolean getWantClientAuth() {
            return (flags.get() & FL_WANT_C_AUTH) != 0;
        }

        public void setEnableSessionCreation(final boolean flag) {
            final AtomicInteger flags = this.flags;
            int oldVal, newVal;
            do {
                oldVal = flags.get();
                if (((oldVal & FL_SESSION_CRE) != 0) == flag) {
                    return;
                }
                newVal = oldVal ^ FL_SESSION_CRE;
            } while (! flags.compareAndSet(oldVal, newVal));
        }

        public boolean getEnableSessionCreation() {
            return (flags.get() & FL_SESSION_CRE) != 0;
        }
    }

    static final SSLEngine CLOSED_STATE = new SSLEngine() {
        public SSLEngineResult wrap(final ByteBuffer[] srcs, final int offset, final int length, final ByteBuffer dst) throws SSLException {
            throw ElytronMessages.log.sslClosed();
        }

        public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts, final int offset, final int length) throws SSLException {
            throw ElytronMessages.log.sslClosed();
        }

        public Runnable getDelegatedTask() {
            return null;
        }

        public void closeInbound() throws SSLException {
        }

        public boolean isInboundDone() {
            return true;
        }

        public void closeOutbound() {

        }

        public boolean isOutboundDone() {
            return true;
        }

        public String[] getSupportedCipherSuites() {
            throw Assert.unsupported();
        }

        public String[] getEnabledCipherSuites() {
            throw Assert.unsupported();
        }

        public void setEnabledCipherSuites(final String[] suites) {
            throw Assert.unsupported();
        }

        public String[] getSupportedProtocols() {
            throw Assert.unsupported();
        }

        public String[] getEnabledProtocols() {
            throw Assert.unsupported();
        }

        public void setEnabledProtocols(final String[] protocols) {
            throw Assert.unsupported();
        }

        public SSLSession getSession() {
            return null;
        }

        public void beginHandshake() throws SSLException {
            throw ElytronMessages.log.sslClosed();
        }

        public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }

        public void setUseClientMode(final boolean mode) {
            throw Assert.unsupported();
        }

        public boolean getUseClientMode() {
            return false;
        }

        public void setNeedClientAuth(final boolean need) {
        }

        public boolean getNeedClientAuth() {
            return false;
        }

        public void setWantClientAuth(final boolean want) {
        }

        public boolean getWantClientAuth() {
            return false;
        }

        public void setEnableSessionCreation(final boolean flag) {
        }

        public boolean getEnableSessionCreation() {
            return false;
        }
    };
}
