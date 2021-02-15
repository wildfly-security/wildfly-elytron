/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;

/**
 * SSLContext that resolves which SSLContext to use based on peer's host and port information.
 */
public final class DynamicSSLContext extends SSLContext {

    private static SSLContext resolverSSLContext(DynamicSSLContextSPI dynamicSSLContextSPIImpl) throws NoSuchAlgorithmException, DynamicSSLContextException {
        return dynamicSSLContextSPIImpl.getConfiguredDefault() == null ?
                SSLContext.getDefault() : dynamicSSLContextSPIImpl.getConfiguredDefault();
    }

    /**
     * This constructor uses ServiceLoader to find provider of DynamicSSLContextSPI on classpath.
     */
    public DynamicSSLContext() throws NoSuchAlgorithmException {
        // this does not use provider and protocol from DynamicSSLContextSPI implementation found on classpath
        // to avoid this ServiceLoader.load would have to be called 3 times in separate static method
        super(new DynamicSSLContextSpiImpl(), SSLContext.getDefault().getProvider(), SSLContext.getDefault().getProtocol());
    }

    /**
     * This constructor uses received DynamicSSLContextSPI implementation or finds it on classpath if received is null.
     *
     * @param dynamicSSLContextSPIImpl DynamicSSLContextSPI implementation to use. If null then ServiceLoader is used to locate it on classpath.
     */
    public DynamicSSLContext(DynamicSSLContextSPI dynamicSSLContextSPIImpl) throws NoSuchAlgorithmException, DynamicSSLContextException {
        super(new DynamicSSLContextSpiImpl(dynamicSSLContextSPIImpl),
                resolverSSLContext(dynamicSSLContextSPIImpl).getProvider(),
                resolverSSLContext(dynamicSSLContextSPIImpl).getProtocol());
    }
}
