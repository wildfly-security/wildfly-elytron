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
package org.wildfly.security.auth.client;

import java.security.Provider;
import java.util.function.Supplier;

import javax.security.sasl.SaslClientFactory;

/**
 * An {@link AuthenticationConfiguration} to return a {@link SaslClientFactory}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SetSaslClientFactoryAuthenticationConfiguration extends AuthenticationConfiguration {

    private final Supplier<SaslClientFactory> saslClientFactorySupplier;

    SetSaslClientFactoryAuthenticationConfiguration(final AuthenticationConfiguration parent, final Supplier<SaslClientFactory> saslClientFactorySupplier) {
        super(parent);
        this.saslClientFactorySupplier = saslClientFactorySupplier;
    }

    @Override
    SaslClientFactory getSaslClientFactory(Supplier<Provider[]> providers) {
        return saslClientFactorySupplier.get();
    }

    @Override
    AuthenticationConfiguration reparent(AuthenticationConfiguration newParent) {
        return new SetSaslClientFactoryAuthenticationConfiguration(newParent, saslClientFactorySupplier);
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("SaslClientFactory,");
    }

}
