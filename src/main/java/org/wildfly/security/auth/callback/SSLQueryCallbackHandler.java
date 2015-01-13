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

package org.wildfly.security.auth.callback;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * A callback handler which delegates to another callback handler, passing the authentication's SSL/TLS information to that
 * callback handler on its first invocation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLQueryCallbackHandler implements CallbackHandler {
    private final CallbackHandler delegate;
    private final SSLContext sslContext;
    private final SSLEngine sslEngine;
    private final SSLSocket sslSocket;

    private final AtomicBoolean once = new AtomicBoolean();

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate callback handler
     * @param sslContext the SSL context used
     * @param sslEngine the SSL engine of the connection
     */
    public SSLQueryCallbackHandler(final CallbackHandler delegate, final SSLContext sslContext, final SSLEngine sslEngine) {
        this.delegate = delegate;
        this.sslContext = sslContext;
        this.sslEngine = sslEngine;
        sslSocket = null;
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate callback handler
     * @param sslContext the SSL context used
     * @param sslSocket the SSL socket
     */
    public SSLQueryCallbackHandler(final CallbackHandler delegate, final SSLContext sslContext, final SSLSocket sslSocket) {
        this.delegate = delegate;
        this.sslContext = sslContext;
        this.sslSocket = sslSocket;
        sslEngine = null;
    }

    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (! once.compareAndSet(false, true)) {
            delegate.handle(callbacks);
            return;
        }
        final int length = callbacks.length;
        final Callback[] newCallbacks = new Callback[length + 1];
        newCallbacks[0] = sslEngine != null ? new SSLCallback(sslContext, sslEngine) : new SSLCallback(sslContext, sslSocket);
        System.arraycopy(callbacks, 0, newCallbacks, 1, length);
        try {
            delegate.handle(newCallbacks);
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() instanceof SSLCallback) {
                delegate.handle(callbacks);
                return;
            }
            throw e;
        }
    }
}
