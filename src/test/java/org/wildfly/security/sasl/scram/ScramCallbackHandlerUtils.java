/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
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
package org.wildfly.security.sasl.scram;

import java.net.URI;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.password.Password;

/**
 * @author Kabir Khan
 */
class ScramCallbackHandlerUtils {

    static CallbackHandler createClientCallbackHandler(final String username, final char[] password) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY
                                .useName(username)
                                .usePassword(password)
                                .allowSaslMechanisms("SCRAM-SHA-256"));


        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }

    static CallbackHandler createClientCallbackHandler(final String username, final Password password) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.EMPTY
                                .useName(username)
                                .usePassword(password)
                                .allowSaslMechanisms("SCRAM-SHA-256"));


        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }
}
