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

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * A {@link HttpServerAuthenticationMechanismFactory} that adds a predefined set of properties to all calls to the delegate.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class PropertiesServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory delegate;
    private final Map<String, ?> properties;

    /**
     * Construct a new instance.
     *
     * @param delegate the {@link HttpServerAuthenticationMechanismFactory} calls are delegated to.
     * @param properties the properties that should be added to any properties passed in overriding any duplicate keys.
     */
    public PropertiesServerMechanismFactory(final HttpServerAuthenticationMechanismFactory delegate, final Map<String, ?> properties) {
        this.delegate = checkNotNullParam("delegate", delegate);
        this.properties = new HashMap<>(checkNotNullParam("properties", properties));
    }

    /**
     * Obtain the list of available mechanism names after merging the properties.
     *
     * @param properties the initial set of properties to pass to the delegate to obtain the mechanism names.
     * @return the list of authentication mechanisms available form this factory.
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        return delegate.getMechanismNames(combine(properties, this.properties));
    }

    /**
     * Create an instance of the requested {@link HttpServerAuthenticationMechanismFactory}.
     *
     * @param mechanismName the name of the mechanism being requested.
     * @param properties initial properties to be passed into the delegate factory.
     * @param callbackHandler the {@link CallbackHandler} to use for verification.
     * @return The newly created {@link HttpServerAuthenticationMechanismFactory}, or {@code null} if not availbale.
     * @throws HttpAuthenticationException
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String,
     * java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        return delegate.createAuthenticationMechanism(mechanismName, combine(properties, this.properties), callbackHandler);
    }

    private static Map<String, ?> combine(Map<String, ?> provided, Map<String, ?> configured) {
        Map<String, Object> combined = new HashMap<>(provided);
        combined.putAll( configured);

        return combined;
    }

}
