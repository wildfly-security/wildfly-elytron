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

package org.wildfly.security.sasl.auth.util;

import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.common.function.ExceptionUnaryOperator;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.sasl.util.AbstractDelegatingSaslServer;

/**
 * A delegating {@link SaslServer} which establishes a specific {@link AuthenticationContext} for the duration
 * of the authentication process.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationContextSaslServer extends AbstractDelegatingSaslServer {

    private AuthenticationContext context;
    private ExceptionUnaryOperator<byte[], SaslException> responseAction = delegate::evaluateResponse;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server
     * @param context the authentication context to use
     */
    public AuthenticationContextSaslServer(final SaslServer delegate, final AuthenticationContext context) {
        super(delegate);
        this.context = context;
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server
     */
    public AuthenticationContextSaslServer(final SaslServer delegate) {
        super(delegate);
        context = AuthenticationContext.captureCurrent();
    }

    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        return context.runExFunction(responseAction, response);
    }

    public void dispose() throws SaslException {
        try {
            super.dispose();
        } finally {
            context = null;
            responseAction = null;
        }
    }
}
