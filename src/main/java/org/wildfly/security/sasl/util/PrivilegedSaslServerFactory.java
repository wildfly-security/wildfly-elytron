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

import java.security.AccessControlContext;
import java.security.AccessController;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

/**
 * A {@code SaslServerFactory} whose {@code SaslServer} instances evaluate challenges and wrap/unwrap requests in a
 * privileged context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PrivilegedSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    private final AccessControlContext context;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     */
    public PrivilegedSaslServerFactory(final SaslServerFactory delegate) {
        this(delegate, AccessController.getContext());
    }

    PrivilegedSaslServerFactory(final SaslServerFactory delegate, final AccessControlContext context) {
        super(delegate);
        this.context = context;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslServer saslServer = delegate.createSaslServer(mechanism, protocol, serverName, props, cbh);
        return saslServer == null ? null : new PrivilegedSaslServer(saslServer, context);
    }
}
