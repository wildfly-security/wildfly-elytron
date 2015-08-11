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

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * A {@link HttpServerAuthenticationMechanismFactory} which locates further factory implementations by iterating a {@link ServiceLoader}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class ServiceLoaderMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final ServiceLoader<HttpServerAuthenticationMechanismFactory> serviceLoader;

    /**
     * Constructs a new instance with a previously created {@link ServiceLoader}
     *
     * This class synchronizes on the supplied service loader, if the same is synchronized against outside then {@link ServiceLoader#reload()} can safely be called.
     *
     * @param serviceLoader the {@link ServiceLoader} to use to locate {@link HttpServerAuthenticationMechanismFactory} instances.
     */
    public ServiceLoaderMechanismFactory(ServiceLoader<HttpServerAuthenticationMechanismFactory> serviceLoader) {
        this.serviceLoader = checkNotNullParam("serviceLoader", serviceLoader);
    }

    /**
     * Constructs a new instance, a {@link ServiceLoader} will be created from the supplied {@link ClassLoader}
     *
     * @param classLoader the {@link ClassLoader} to use to construct a {@link ServiceLoader}.
     */
    public ServiceLoaderMechanismFactory(ClassLoader classLoader) {
        this(ServiceLoader.load(HttpServerAuthenticationMechanismFactory.class, checkNotNullParam("classLoader", classLoader)));
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        Set<String> mechanismNames = new LinkedHashSet<>();
        synchronized(serviceLoader) {
            Iterator<HttpServerAuthenticationMechanismFactory> factoryIterator = serviceLoader.iterator();
            try {
                while (factoryIterator.hasNext()) {
                    HttpServerAuthenticationMechanismFactory current = factoryIterator.next();
                    Collections.addAll(mechanismNames, current.getMechanismNames(properties));
                }
            } catch (ServiceConfigurationError e) {
                log.debug(e);
            }
        }
        return mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties,
            CallbackHandler callbackHandler) {
        synchronized(serviceLoader) {
            Iterator<HttpServerAuthenticationMechanismFactory> factoryIterator = serviceLoader.iterator();
            try {
                while (factoryIterator.hasNext()) {
                    HttpServerAuthenticationMechanismFactory current = factoryIterator.next();
                    HttpServerAuthenticationMechanism authenticationMechanism = current.createAuthenticationMechanism(mechanismName, properties, callbackHandler);
                    if (authenticationMechanism != null) {
                        return authenticationMechanism;
                    }
                }
            } catch (ServiceConfigurationError e) {
                log.debug(e);
            }
        }
        return null;
    }

}
