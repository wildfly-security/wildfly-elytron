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

import static org.wildfly.security.http.HttpConstants.BASIC;

import java.util.ArrayList;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.kohsuke.MetaInfServices;
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
        mechanismNames.add(BASIC);


        return mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties,
            CallbackHandler callbackHandler) {
        switch (mechanismName) {
            case BASIC:
                return new BasicAuthenticationMechanism(callbackHandler, "Elytron Realm", false);
        }
        return null;
    }
}
