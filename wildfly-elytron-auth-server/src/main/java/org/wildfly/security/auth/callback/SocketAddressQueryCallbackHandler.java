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

package org.wildfly.security.auth.callback;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * A callback handler which delegates to another callback handler, passing the local and/or peer socket address to that
 * callback handler on its first invocation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SocketAddressQueryCallbackHandler implements CallbackHandler {
    private final CallbackHandler delegate;
    private final SocketAddress localAddress;
    private final SocketAddress peerAddress;

    private final AtomicBoolean once = new AtomicBoolean();

    /**
     * Construct a new instance.
     *
     * @param delegate the callback handler to delegate to
     * @param localAddress the local socket address
     * @param peerAddress the peer socket address
     */
    public SocketAddressQueryCallbackHandler(final CallbackHandler delegate, final SocketAddress localAddress, final SocketAddress peerAddress) {
        this.delegate = delegate;
        this.localAddress = localAddress;
        this.peerAddress = peerAddress;
    }

    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (localAddress == null && peerAddress == null || ! once.compareAndSet(false, true)) {
            delegate.handle(callbacks);
            return;
        }
        final SocketAddressCallback localCallback = localAddress == null ? null : new SocketAddressCallback(localAddress, SocketAddressCallback.Kind.LOCAL);
        final SocketAddressCallback peerCallback = peerAddress == null ? null : new SocketAddressCallback(peerAddress, SocketAddressCallback.Kind.PEER);
        final Callback[] newCallbacks;
        final int length = callbacks.length;
        if (localCallback != null && peerCallback != null) {
            newCallbacks = new Callback[length + 2];
            newCallbacks[0] = localCallback;
            newCallbacks[1] = peerCallback;
            System.arraycopy(callbacks, 0, newCallbacks, 2, length);
        } else if (localCallback != null) {
            newCallbacks = new Callback[length + 1];
            newCallbacks[0] = localCallback;
            System.arraycopy(callbacks, 0, newCallbacks, 1, length);
        } else {
            // peerCallback != null
            newCallbacks = new Callback[length + 1];
            newCallbacks[0] = peerCallback;
            System.arraycopy(callbacks, 0, newCallbacks, 1, length);
        }
        try {
            delegate.handle(newCallbacks);
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() instanceof SocketAddressCallback) {
                delegate.handle(callbacks);
                return;
            }
            throw e;
        }
    }
}
