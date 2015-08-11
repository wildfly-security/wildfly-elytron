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
package org.wildfly.security.http.util;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.common.Assert.checkNotNullParam;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityProviderHttpMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private static final String SERVICE_TYPE = HttpServerAuthenticationMechanismFactory.class.getSimpleName();

    private final Supplier<Provider[]> providers;

    public SecurityProviderHttpMechanismFactory(Supplier<Provider[]> providers) {
        this.providers = checkNotNullParam("providers", providers);
    }

    public SecurityProviderHttpMechanismFactory() {
        this(Security::getProviders);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        Set<String> mechanismNames = new LinkedHashSet<>();
        for (Provider current : providers.get()) {
            Set<Service> services = current.getServices();
            if (services != null) {
                for (Service currentService : services) {
                    if (SERVICE_TYPE.equals(currentService.getType())) {
                        try {
                            String[] serviceMechNames = ((HttpServerAuthenticationMechanismFactory) currentService.newInstance(null)).getMechanismNames(properties);
                            Collections.addAll(mechanismNames, serviceMechNames);
                        } catch (NoSuchAlgorithmException e) {
                            log.debug(e);
                        }
                    }
                }
            }
        }
        return mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) {
        for (Provider current : providers.get()) {
            Set<Service> services = current.getServices();
            if (services != null) {
                for (Service currentService : services) {
                    if (SERVICE_TYPE.equals(currentService.getType())) {
                        try {
                            HttpServerAuthenticationMechanismFactory factory = (HttpServerAuthenticationMechanismFactory) currentService.newInstance(null);
                            HttpServerAuthenticationMechanism mechanism = factory.createAuthenticationMechanism(mechanismName, properties, callbackHandler);
                            if (mechanism != null) {
                                return mechanism;
                            }
                        } catch (NoSuchAlgorithmException e) {
                            log.debug(e);
                        }
                    }
                }
            }
        }
        return null;
    }

}
