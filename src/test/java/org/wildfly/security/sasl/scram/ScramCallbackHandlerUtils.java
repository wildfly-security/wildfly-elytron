/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.sasl.scram;

import java.net.URI;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.password.Password;
import org.wildfly.security.sasl.SaslMechanismSelector;

/**
 * @author Kabir Khan
 */
class ScramCallbackHandlerUtils {

    static CallbackHandler createClientCallbackHandler(final String username, final char[] password) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .usePassword(password)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("SCRAM-SHA-256")));


        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }

    static CallbackHandler createClientCallbackHandler(final String username, final Password password) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .usePassword(password)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("SCRAM-SHA-256")));


        return ClientUtils.getCallbackHandler(new URI("remote://localhost"), context);
    }
}
