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

import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslException;

/**
 * An abstract base for {@link SaslServer} instances which delegate to another {@code SaslServer}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractDelegatingSaslServer implements SaslServer, SaslWrapper {

    /**
     * The delegate {@code SaslServer}.
     */
    protected final SaslServer delegate;

    /**
     * Construct a new instance.
     *
     * @param delegate the SASL server to delegate to
     */
    protected AbstractDelegatingSaslServer(final SaslServer delegate) {
        this.delegate = delegate;
    }

    public String getMechanismName() {
        return delegate.getMechanismName();
    }

    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        return delegate.evaluateResponse(response);
    }

    public String getAuthorizationID() {
        return delegate.getAuthorizationID();
    }

    public boolean isComplete() {
        return delegate.isComplete();
    }

    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        return delegate.unwrap(incoming, offset, len);
    }

    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        return delegate.wrap(outgoing, offset, len);
    }

    public Object getNegotiatedProperty(final String propName) {
        return delegate.getNegotiatedProperty(propName);
    }

    public void dispose() throws SaslException {
        delegate.dispose();
    }
}
