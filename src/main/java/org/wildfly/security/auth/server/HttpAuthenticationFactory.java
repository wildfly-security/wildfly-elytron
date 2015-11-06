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
package org.wildfly.security.auth.server;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.common.Assert;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * A HTTP authentication mechanism configuration, the configuration is associated with the {@link SecurityDomain} and
 * {@link HttpServerAuthenticationMechanismFactory} for obtaining configured mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class HttpAuthenticationFactory extends AbstractMechanismAuthenticationFactory<HttpServerAuthenticationMechanism, HttpAuthenticationException> {

    private final HttpServerAuthenticationMechanismFactory mechanismFactory;

    HttpAuthenticationFactory(final SecurityDomain securityDomain, final Map<String, MechanismConfiguration> mechanismConfigurations, final HttpServerAuthenticationMechanismFactory mechanismFactory) {
        super(securityDomain, mechanismConfigurations);
        this.mechanismFactory = mechanismFactory;
    }

    HttpServerAuthenticationMechanism doCreate(final String name, final CallbackHandler callbackHandler) throws HttpAuthenticationException {
        return mechanismFactory.createAuthenticationMechanism(name, Collections.emptyMap(), callbackHandler);
    }

    Collection<String> getAllSupportedMechNames() {
        return Arrays.asList(mechanismFactory.getMechanismNames(Collections.emptyMap()));
    }

    /**
     * Get the {@link HttpServerAuthenticationMechanismFactory} associated with this configuration.
     *
     * @return the {@link HttpServerAuthenticationMechanismFactory} associated with this configuration.
     */
    public HttpServerAuthenticationMechanismFactory getMechanismFactory() {
        return mechanismFactory;
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link HttpAuthenticationFactory}.
     *
     * @return a new {@link Builder} capable of building a {@link HttpAuthenticationFactory}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for SASL server factory configurations.
     */
    public static final class Builder extends AbstractMechanismAuthenticationFactory.Builder<HttpServerAuthenticationMechanism, HttpAuthenticationException> {
        private HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory = null; // TODO: empty factory

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        public Builder setSecurityDomain(final SecurityDomain securityDomain) {
            super.setSecurityDomain(securityDomain);
            return this;
        }

        public Builder addMechanism(final String mechanismName, final MechanismConfiguration mechanismConfiguration) {
            super.addMechanism(mechanismName, mechanismConfiguration);
            return this;
        }

        /**
         * Set the HTTP server authentication mechanism factory to use.
         *
         * @param httpServerAuthenticationMechanismFactory the factory (may not be {@code null})
         */
        public Builder setHttpServerAuthenticationMechanismFactory(final HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory) {
            Assert.checkNotNullParam("httpServerAuthenticationMechanismFactory", httpServerAuthenticationMechanismFactory);
            this.httpServerAuthenticationMechanismFactory = httpServerAuthenticationMechanismFactory;
            return this;
        }

        public HttpAuthenticationFactory build() {
            return new HttpAuthenticationFactory(getSecurityDomain(), getMechanismConfigurations(), httpServerAuthenticationMechanismFactory);
        }
    }
}
