/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.dynamic.ssl;

import org.wildfly.common.Assert;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SSLSocketFactory that is being used by DynamicSSLContext.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Krepinska</a>
 */
final class DynamicSSLSocketFactory extends SSLSocketFactory {

    private DynamicSSLContextSPI dynamicSSLContextImpl;
    private volatile String[] intersectionCipherSuite;
    private SSLSocketFactory configuredDefaultSslSocketFactory;

    DynamicSSLSocketFactory(SSLSocketFactory configuredDefaultSslSocketFactory, DynamicSSLContextSPI dynamicSSLContextImpl) {
        super();
        Assert.assertNotNull(configuredDefaultSslSocketFactory);
        Assert.assertNotNull(dynamicSSLContextImpl);
        this.configuredDefaultSslSocketFactory = configuredDefaultSslSocketFactory;
        this.dynamicSSLContextImpl = dynamicSSLContextImpl;
    }

    @Override
    public Socket createSocket() throws IOException {
        return configuredDefaultSslSocketFactory.createSocket();
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return createSocketBasedOnPeerInfo(null, port, address, null, null, null, null);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return createSocketBasedOnPeerInfo(host, port, null, null, null, null, null);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
        return createSocketBasedOnPeerInfo(host, port, null, localAddress, localPort, null, null);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return createSocketBasedOnPeerInfo(null, port, address, localAddress, localPort, null, null);
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return createSocketBasedOnPeerInfo(host, port, null, null, null, socket, autoClose);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return configuredDefaultSslSocketFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        String[] val = intersectionCipherSuite;
        if (val == null) {
            synchronized (this) {
                val = intersectionCipherSuite;
                if (intersectionCipherSuite == null) {
                    val = intersectionCipherSuite = getIntersection();
                }
            }
        }
        return val;
    }

    private Socket createSocketBasedOnPeerInfo(String hostname, Integer port, InetAddress address, InetAddress localAddress, Integer localPort, Socket socket, Boolean autoClose) throws IOException {
        try {
            SSLContext sslContext = this.dynamicSSLContextImpl.getSSLContext(new URI(null, null, hostname == null ? address.getHostName() : hostname, port, null, null, null));
            if (sslContext == null) {
                throw ElytronMessages.log.configuredSSLContextIsNull();
            }
            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            if (socketFactory instanceof DynamicSSLSocketFactory && socketFactory.equals(this)) {
                throw ElytronMessages.log.dynamicSSLContextCreatesLoop();
            }
            // resolve socket
            if (socket != null && autoClose != null) {
                return socketFactory.createSocket(socket, hostname, port, autoClose);
            }

            // resolves InetAddresses callbacks
            if (address != null) {
                return localAddress == null ?
                        socketFactory.createSocket(address, port) : socketFactory.createSocket(address, port, localAddress, localPort);
            }
            if (localAddress != null && localPort != null) {
                return socketFactory.createSocket(hostname, port, localAddress, localPort);
            }
            return socketFactory.createSocket(hostname, port);
        } catch (URISyntaxException e) {
            throw new UnknownHostException(e.getMessage());
        } catch (DynamicSSLContextException e) {
            throw new IOException(e);
        }
    }

    private String[] getIntersection() {
        List<SSLContext> sslContexts;
        try {
            sslContexts = dynamicSSLContextImpl.getConfiguredSSLContexts();
        } catch (DynamicSSLContextException e) {
            throw ElytronMessages.log.unableToGetConfiguredSSLContexts();
        }
        if (sslContexts == null) {
            throw ElytronMessages.log.configuredSSLContextsAreNull();
        }
        Map<String, Integer> counts = new HashMap<>();
        List<String> intersection = new ArrayList<>();
        sslContexts.forEach(c -> {
            String[] cipherSuites = c.getSocketFactory().getSupportedCipherSuites();
            for (String cipherSuite : cipherSuites) {
                counts.merge(cipherSuite, 1, (a, b) -> a + b);
            }
        });
        List<SSLContext> finalSslContexts = sslContexts;
        counts.forEach((c, v) -> {
            if (finalSslContexts.size() == v) {
                intersection.add(c);
            }
        });
        return intersection.toArray(new String[0]);
    }
}
