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

package org.jboss.sasl.anonymous;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.util.Map;

/**
 * The client factory for the anonymous SASL mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AnonymousClientFactory extends AbstractAnonymousFactory implements SaslClientFactory {

    public String[] getMechanismNames(Map<String, ?> props) {
        return super.getMechanismNames(props);
    }

    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
        // Only return a client if we are sure anonymous is supported.
        if (includesAnonymous(mechanisms) == false || anonymousCompatible(props) == false) {
            return null;
        }

        return new AnonymousSaslClient(protocol, serverName, cbh, authorizationId);
    }

    private boolean includesAnonymous(final String[] mechanisms) {
        for (String current : mechanisms) {
            if (ANONYMOUS.equals(current)) {
                return true;
            }
        }
        return false;
    }

}
