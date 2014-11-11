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

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import java.util.Map;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * The server factory for the plain SASL mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(SaslServerFactory.class)
public class PlainSaslServerFactory implements SaslServerFactory {

    /**
     * Default constructor.
     */
    public PlainSaslServerFactory() {
    }

    public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
        // Unless we are sure plain is required don't return a SaslServer
        return PlainSasl.PLAIN.equals(mechanism) && PlainSasl.isMatched(props) ? new PlainSaslServer(cbh) : null;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return PlainSasl.isMatched(props) ? PlainSasl.NAMES.clone() : WildFlySasl.NO_NAMES;
    }
}
