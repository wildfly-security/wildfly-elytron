/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.util;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.SocketAddressCallback;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.HttpServerRequest;

/**
 * A wrapper {@link HttpServerAuthenticationMechanismFactory} that sets the peer address using the current
 * authentication request.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class SocketAddressCallbackServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory delegate;

    /**
     * Construct a wrapping mechanism factory instance.
     *
     * @param delegate the wrapped mechanism factory
     */
    public SocketAddressCallbackServerMechanismFactory(final HttpServerAuthenticationMechanismFactory delegate) {
        this.delegate = checkNotNullParam("delegate", delegate);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        return delegate.getMechanismNames(properties);
    }

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        final HttpServerAuthenticationMechanism mechanism = delegate.createAuthenticationMechanism(mechanismName, properties, callbackHandler);
        return mechanism != null ? new HttpServerAuthenticationMechanism() {

            @Override
            public String getMechanismName() {
                return mechanism.getMechanismName();
            }

            @Override
            public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
                final InetSocketAddress peerAddress = request.getSourceAddress();
                if (peerAddress != null) {
                    final SocketAddressCallback peerCallback = new SocketAddressCallback(peerAddress, SocketAddressCallback.Kind.PEER);
                    try {
                        callbackHandler.handle(new Callback[] { peerCallback });
                    } catch (IOException | UnsupportedCallbackException e) {
                        throw new HttpAuthenticationException(e);
                    }
                }

                mechanism.evaluateRequest(request);
            }
        } : null;
    }
}

