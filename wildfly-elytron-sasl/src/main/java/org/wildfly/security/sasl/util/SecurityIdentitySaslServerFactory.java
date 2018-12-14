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

import static org.wildfly.security.sasl._private.ElytronMessages.sasl;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * A SASL server factory which makes the authenticated {@link SecurityIdentity} available to the caller.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityIdentitySaslServerFactory extends AbstractDelegatingSaslServerFactory {

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     */
    public SecurityIdentitySaslServerFactory(final SaslServerFactory delegate) {
        super(delegate);
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslServer delegateSaslServer = delegate.createSaslServer(mechanism, protocol, serverName, props, cbh);
        return delegateSaslServer == null ? null : new AbstractDelegatingSaslServer(delegateSaslServer) {
            private final AtomicBoolean complete = new AtomicBoolean();
            private volatile SecurityIdentity securityIdentity;

            public byte[] evaluateResponse(final byte[] response) throws SaslException {
                final byte[] challenge = delegate.evaluateResponse(response);
                if (isComplete() && complete.compareAndSet(false, true)) try {
                    final SecurityIdentityCallback ric = new SecurityIdentityCallback();
                    cbh.handle(new Callback[] { ric });
                    securityIdentity = ric.getSecurityIdentity();
                } catch (Throwable ignored) {
                }
                return challenge;
            }

            public Object getNegotiatedProperty(final String propName) {
                if (! isComplete()) {
                    throw sasl.mechAuthenticationNotComplete();
                }
                return propName.equals(WildFlySasl.SECURITY_IDENTITY) ? securityIdentity : super.getNegotiatedProperty(propName);
            }

            public void dispose() throws SaslException {
                try {
                    super.dispose();
                } finally {
                    securityIdentity = null;
                }
            }
        };
    }
}
