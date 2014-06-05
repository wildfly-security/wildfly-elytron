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

package org.wildfly.sasl.plain;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import java.util.Map;

import org.wildfly.sasl.util.AbstractSaslFactory;

/**
 * The server factory for the plain SASL mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PlainServerFactory extends AbstractSaslFactory implements SaslServerFactory {

    /**
     * The PLAIN mechanism name
     */
    public static final String PLAIN = "PLAIN";

    /**
     * Default constructor.
     */
    public PlainServerFactory() {
        this(PLAIN);
    }

    /**
     * Construct a new instance.
     *
     * @param name the mechanism name
     */
    protected PlainServerFactory(final String name) {
        super(name);
    }

    public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
        // Unless we are sure plain is required don't return a SaslServer
        if (PLAIN.equals(mechanism) == false || matches(props) == false) {
            return null;
        }

        return new PlainSaslServer(protocol, serverName, cbh);
    }

    @Override
    protected boolean isAnonymous() {
        return false;
    }

}
