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

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * SSLContextSpi that uses ServiceLoader to find implementations of DynamicSSLContextSPI.
 * DynamicSSLContextSPI implementation is being used to obtain authentication configuration for DynamicSSLContext.
 * if no provider is found then SSLContext.getDefault() is used.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Krepinska</a>
 */
final class DynamicSSLContextSpiImpl extends SSLContextSpi {

    private final DynamicSSLContextSPI dynamicSSLContextImpl;
    private volatile SSLSocketFactory sslSocketFactory;

    DynamicSSLContextSpiImpl() {
        this(null);
    }

    DynamicSSLContextSpiImpl(DynamicSSLContextSPI dynamicSSLContextSPIImpl) {
        if (dynamicSSLContextSPIImpl != null) {
            dynamicSSLContextImpl = dynamicSSLContextSPIImpl;
        } else {
            Iterator<DynamicSSLContextSPI> dynamicSSLContextSPIIterator = ServiceLoader.load(DynamicSSLContextSPI.class).iterator();
            if (dynamicSSLContextSPIIterator.hasNext()) {
                dynamicSSLContextImpl = dynamicSSLContextSPIIterator.next();
            } else {
                dynamicSSLContextImpl = null;
            }
        }
    }

    private SSLContext getConfiguredDefaultSSLContext() {
        try {
            if (dynamicSSLContextImpl != null) {
                SSLContext configuredDefault = dynamicSSLContextImpl.getConfiguredDefault();
                if (configuredDefault != null) {
                    return configuredDefault;
                }
            }
            return SSLContext.getDefault();
        } catch (NoSuchAlgorithmException | DynamicSSLContextException e) {
            throw ElytronMessages.log.cannotObtainConfiguredDefaultSSLContext();
        }
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) {
        // initialization of SSL context is delegated to providers of {@link org.wildfly.security.dynamic.ssl.DynamicSSLContextSPI}
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        if (dynamicSSLContextImpl == null) {
            return this.getConfiguredDefaultSSLContext().getSocketFactory();
        }
        if (sslSocketFactory == null) {
            synchronized (this) {
                if (sslSocketFactory == null) {
                    sslSocketFactory = new DynamicSSLSocketFactory(this.getConfiguredDefaultSSLContext().getSocketFactory(), dynamicSSLContextImpl);
                }
            }
        }
        return sslSocketFactory;
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return this.getConfiguredDefaultSSLContext().getServerSocketFactory();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return this.getConfiguredDefaultSSLContext().createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) throws IllegalStateException {
        try {
            if (dynamicSSLContextImpl == null) {
                return this.getConfiguredDefaultSSLContext().createSSLEngine(host, port);
            }
            SSLContext sslContext = dynamicSSLContextImpl
                    .getSSLContext(new URI(null, null, host, port, null, null, null));
            if (sslContext == null) {
                throw ElytronMessages.log.receivedSSLContextFromDynamicSSLContextProviderWasNull();
            }
            if (sslContext instanceof DynamicSSLContext && sslContext.getSocketFactory().equals(this.engineGetSocketFactory())) {
                throw ElytronMessages.log.dynamicSSLContextCreatesLoop();
            }
            return sslContext.createSSLEngine(host, port);
        } catch (URISyntaxException e) {
            throw ElytronMessages.log.couldNotCreateURI();
        } catch (DynamicSSLContextException e) {
            throw ElytronMessages.log.couldNotCreateDynamicSSLContextEngine();
        }
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        throw new UnsupportedOperationException(ElytronMessages.log.dynamicSSLContextDoesNotSupportSessions());
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        throw new UnsupportedOperationException(ElytronMessages.log.dynamicSSLContextDoesNotSupportSessions());
    }

    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {
        return this.getConfiguredDefaultSSLContext().getSupportedSSLParameters();
    }
}
