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
package org.wildfly.security.http.impl;

import static org.wildfly.security.http.HttpConstants.BASIC_NAME;
import static org.wildfly.security.http.HttpConstants.CLIENT_CERT_NAME;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.kohsuke.MetaInfServices;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * The {@link HttpServerAuthenticationMechanismFactory} implementation for the mechanisms implemented within Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MetaInfServices(value = HttpServerAuthenticationMechanismFactory.class)
public class ServerMechanismFactoryImpl implements HttpServerAuthenticationMechanismFactory {

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        // TODO We may cache this later but for now leave the option open for properties to influence selection.
        ArrayList<String> mechanismNames = new ArrayList<>();
        mechanismNames.add(BASIC_NAME);
        mechanismNames.add(CLIENT_CERT_NAME);

        return mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        switch (mechanismName) {
            case BASIC_NAME:
                String[] realms = null;
                final AvailableRealmsCallback availableRealmsCallback = new AvailableRealmsCallback();
                try {
                    callbackHandler.handle(new Callback[] { availableRealmsCallback });
                    realms = availableRealmsCallback.getRealmNames();
                } catch (UnsupportedCallbackException ignored) {
                } catch (HttpAuthenticationException e) {
                    throw e;
                } catch (IOException e) {
                    throw ElytronMessages.log.mechCallbackHandlerFailedForUnknownReason(mechanismName, e).toHttpAuthenticationException();
                }

                return new BasicAuthenticationMechanism(callbackHandler, realms == null || realms.length == 0 ? null : realms[0], false);
            case CLIENT_CERT_NAME:
                return new ClientCertAuthenticationMechanism(callbackHandler);
        }
        return null;
    }
}
