/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.sasl.plain;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.util.Map;

import org.jboss.sasl.util.AbstractSaslFactory;

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
