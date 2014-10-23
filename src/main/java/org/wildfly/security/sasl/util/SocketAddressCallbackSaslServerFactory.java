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

package org.wildfly.security.sasl.util;

import java.net.SocketAddress;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.SocketAddressQueryCallbackHandler;

/**
 * A {@link SaslServerFactory} which adds {@link org.wildfly.security.auth.callback.SocketAddressCallback SocketAddressCallback} capability to a delegate {@code SaslServerFactory}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SocketAddressCallbackSaslServerFactory implements SaslServerFactory {
    private final SaslServerFactory delegate;
    private final SocketAddress localAddress;
    private final SocketAddress peerAddress;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate server factory
     * @param localAddress the local socket address, or {@code null} if unknown
     * @param peerAddress the peer socket address, or {@code null} if unknown
     */
    public SocketAddressCallbackSaslServerFactory(final SaslServerFactory delegate, final SocketAddress localAddress, final SocketAddress peerAddress) {
        this.delegate = delegate;
        this.localAddress = localAddress;
        this.peerAddress = peerAddress;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslServer(mechanism, protocol, serverName, props, new SocketAddressQueryCallbackHandler(cbh, localAddress, peerAddress));
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return delegate.getMechanismNames(props);
    }
}
