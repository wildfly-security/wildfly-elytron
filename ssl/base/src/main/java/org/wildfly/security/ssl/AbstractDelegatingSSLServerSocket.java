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
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketImplFactory;
import java.nio.channels.ServerSocketChannel;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class AbstractDelegatingSSLServerSocket extends SSLServerSocket {
    private final SSLServerSocket delegate;

    AbstractDelegatingSSLServerSocket(final SSLServerSocket delegate) throws IOException {
        this.delegate = delegate;
    }

    public void bind(final SocketAddress endpoint) throws IOException {
        delegate.bind(endpoint);
    }

    public void bind(final SocketAddress endpoint, final int backlog) throws IOException {
        delegate.bind(endpoint, backlog);
    }

    public InetAddress getInetAddress() {
        return delegate.getInetAddress();
    }

    public int getLocalPort() {
        return delegate.getLocalPort();
    }

    public SocketAddress getLocalSocketAddress() {
        return delegate.getLocalSocketAddress();
    }

    public Socket accept() throws IOException {
        return delegate.accept();
    }

    public void close() throws IOException {
        delegate.close();
    }

    public ServerSocketChannel getChannel() {
        return delegate.getChannel();
    }

    public boolean isBound() {
        return delegate.isBound();
    }

    public boolean isClosed() {
        return delegate.isClosed();
    }

    public void setSoTimeout(final int timeout) throws SocketException {
        delegate.setSoTimeout(timeout);
    }

    public int getSoTimeout() throws IOException {
        return delegate.getSoTimeout();
    }

    public void setReuseAddress(final boolean on) throws SocketException {
        delegate.setReuseAddress(on);
    }

    public boolean getReuseAddress() throws SocketException {
        return delegate.getReuseAddress();
    }

    public String toString() {
        return delegate.toString();
    }

    public static void setSocketFactory(final SocketImplFactory fac) throws IOException {
        ServerSocket.setSocketFactory(fac);
    }

    public void setReceiveBufferSize(final int size) throws SocketException {
        delegate.setReceiveBufferSize(size);
    }

    public int getReceiveBufferSize() throws SocketException {
        return delegate.getReceiveBufferSize();
    }

    public void setPerformancePreferences(final int connectionTime, final int latency, final int bandwidth) {
        delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    public String[] getEnabledCipherSuites() {
        return delegate.getEnabledCipherSuites();
    }

    public void setEnabledCipherSuites(final String[] names) throws IllegalArgumentException {
        delegate.setEnabledCipherSuites(names);
    }

    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    public String[] getSupportedProtocols() {
        return delegate.getSupportedProtocols();
    }

    public String[] getEnabledProtocols() {
        return delegate.getEnabledProtocols();
    }

    public void setEnabledProtocols(final String[] names) throws IllegalArgumentException {
        delegate.setEnabledProtocols(names);
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

    public void setUseClientMode(final boolean clientMode) {
        delegate.setUseClientMode(clientMode);
    }

    public boolean getUseClientMode() {
        return delegate.getUseClientMode();
    }

    public void setEnableSessionCreation(final boolean enabled) {
        delegate.setEnableSessionCreation(enabled);
    }

    public boolean getEnableSessionCreation() {
        return delegate.getEnableSessionCreation();
    }

    public SSLParameters getSSLParameters() {
        return delegate.getSSLParameters();
    }

    public void setSSLParameters(final SSLParameters parameters) {
        delegate.setSSLParameters(parameters);
    }

    protected SSLServerSocket getDelegate() {
        return delegate;
    }
}
