/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.basic.BasicMechanismFactory;
import org.wildfly.security.http.bearer.BearerMechanismFactory;
import org.wildfly.security.http.cert.ClientCertMechanismFactory;
import org.wildfly.security.http.digest.DigestMechanismFactory;
import org.wildfly.security.http.external.ExternalMechanismFactory;
import org.wildfly.security.http.form.FormMechanismFactory;
import org.wildfly.security.http.spnego.SpnegoMechanismFactory;
import org.wildfly.security.http.util.AggregateServerMechanismFactory;

/**
 * An aggregation of the mechanism factories.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Deprecated
public class ServerMechanismFactoryImpl implements HttpServerAuthenticationMechanismFactory {

    private final HttpServerAuthenticationMechanismFactory delegate;

    public ServerMechanismFactoryImpl() {
        delegate = new AggregateServerMechanismFactory(new BasicMechanismFactory(), new BearerMechanismFactory(),
                new ClientCertMechanismFactory(), new DigestMechanismFactory(), new ExternalMechanismFactory(),
                new FormMechanismFactory(), new SpnegoMechanismFactory());
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        return delegate.getMechanismNames(properties);
    }

    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName,
            Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        return delegate.createAuthenticationMechanism(mechanismName, properties, callbackHandler);
    }

}
