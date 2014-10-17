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
 * A {@code SaslWrapper} which encapsulates a {@code SaslServer}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ServerSaslWrapper implements SaslWrapper {
    private final SaslServer saslServer;

    /**
     * Construct a new instance.
     *
     * @param saslServer the {@code SaslServer} to delegate wrap/unwrap calls to.
     */
    public ServerSaslWrapper(final SaslServer saslServer) {
        this.saslServer = saslServer;
    }

    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        return saslServer.wrap(outgoing, offset, len);
    }

    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        return saslServer.unwrap(incoming, offset, len);
    }
}
