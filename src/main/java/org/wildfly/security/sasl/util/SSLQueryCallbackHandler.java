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

package org.wildfly.security.sasl.util;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.SSLCallback;

/**
 * A callback handler which delegates to another callback handler, passing the authentication's SSL/TLS information to that
 * callback handler on its first invocation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SSLQueryCallbackHandler implements CallbackHandler {
    private final CallbackHandler delegate;
    private final Supplier<SSLSession> sslSession;

    private final AtomicBoolean once = new AtomicBoolean(true);

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate callback handler
     * @param sslSession supplier for the current SSL session
     */
    public SSLQueryCallbackHandler(final CallbackHandler delegate, final Supplier<SSLSession> sslSession) {
        this.delegate = delegate;
        this.sslSession = checkNotNullParam("sslSession", sslSession);
    }

    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        SSLSession sslSession;
        if (! once.compareAndSet(true, false) || (sslSession = this.sslSession.get()) == null) {
            delegate.handle(callbacks);
            return;
        }
        final int length = callbacks.length;
        final Callback[] newCallbacks = new Callback[length + 1];
        newCallbacks[0] = new SSLCallback(sslSession);
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

    void activate () {
        once.set(false);
    }

}
