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

import java.util.Enumeration;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class AbstractDelegatingSSLSessionContext implements SSLSessionContext {
    private final SSLSessionContext delegate;

    AbstractDelegatingSSLSessionContext(final SSLSessionContext delegate) {
        this.delegate = delegate;
    }

    public SSLSession getSession(final byte[] sessionId) {
        return delegate.getSession(sessionId);
    }

    public Enumeration<byte[]> getIds() {
        return delegate.getIds();
    }

    public void setSessionTimeout(final int seconds) throws IllegalArgumentException {
        delegate.setSessionTimeout(seconds);
    }

    public int getSessionTimeout() {
        return delegate.getSessionTimeout();
    }

    public void setSessionCacheSize(final int size) throws IllegalArgumentException {
        delegate.setSessionCacheSize(size);
    }

    public int getSessionCacheSize() {
        return delegate.getSessionCacheSize();
    }
}
