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

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

/**
 * A {@code SaslClientFactory} which sets the protocol name to a fixed value, disregarding the passed in value.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ProtocolSaslClientFactory extends AbstractDelegatingSaslClientFactory {
    private final String protocol;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate client factory
     * @param protocol the protocol name to use
     */
    public ProtocolSaslClientFactory(final SaslClientFactory delegate, final String protocol) {
        super(delegate);
        this.protocol = protocol;
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return super.createSaslClient(mechanisms, authorizationId, this.protocol, serverName, props, cbh);
    }
}
