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

package org.wildfly.security.sasl.plain;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * The {@code PLAIN} SASL mechanism client factory implementation.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(SaslClientFactory.class)
public final class PlainSaslClientFactory implements SaslClientFactory {

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        if (PlainSasl.isMatched(props)) for (String mechanism : mechanisms) {
            if (PlainSasl.PLAIN.equals(mechanism)) {
                return new PlainSaslClient(authorizationId, cbh);
            }
        }
        return null;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return PlainSasl.isMatched(props) ? PlainSasl.NAMES.clone() : WildFlySasl.NO_NAMES;
    }
}
