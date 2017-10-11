/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * A {@link HttpServerAuthenticationMechanismFactory} which sorts the mechanism names returned using the provided
 * {@link Comparator}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SortedServerMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory delegate;
    private final Comparator<String> mechanismNameComparator;

    public SortedServerMechanismFactory(final HttpServerAuthenticationMechanismFactory delegate, final Comparator<String> mechanismNameComparator) {
        this.delegate = checkNotNullParam("delegate", delegate);
        this.mechanismNameComparator = checkNotNullParam("mechanismNameComparator", mechanismNameComparator);
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        String[] mechanismNames = delegate.getMechanismNames(properties);
        Arrays.sort(mechanismNames, mechanismNameComparator);
        return mechanismNames;
    }

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties,
            CallbackHandler callbackHandler) throws HttpAuthenticationException {
        return delegate.createAuthenticationMechanism(mechanismName, properties, callbackHandler);
    }

}
