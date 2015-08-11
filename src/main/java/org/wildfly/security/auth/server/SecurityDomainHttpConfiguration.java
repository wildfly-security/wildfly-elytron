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

import org.wildfly.common.Assert;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

/**
 * A HTTP authentication mechanism configuration, the configuration is associated with the {@link SecurityDomain} and
 * {@link HttpServerAuthenticationMechanismFactory} for obtaining configured mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityDomainHttpConfiguration {

    private final SecurityDomain securityDomain;
    private final HttpServerAuthenticationMechanismFactory mechanismFactory;

    public SecurityDomainHttpConfiguration(final SecurityDomain securityDomain, final HttpServerAuthenticationMechanismFactory mechanismFactory) {
        this.securityDomain = Assert.checkNotNullParam("securityDomain", securityDomain);
        // TODO - This will be wrapped to be mechanism specific.
        this.mechanismFactory = Assert.checkNotNullParam("mechanismFactory", mechanismFactory);
    }

    /**
     * Get the {@link SecurityDomain} associated with this configuration.
     *
     * @return the {@link SecurityDomain} associated with this configuration.
     */
    public SecurityDomain getSecurityDomain() {
        return securityDomain;
    }

    /**
     * Get the {@link HttpServerAuthenticationMechanismFactory} associated with this configuration.
     *
     * @return the {@link HttpServerAuthenticationMechanismFactory} associated with this configuration.
     */
    public HttpServerAuthenticationMechanismFactory getMechanismFactory() {
        return mechanismFactory;
    }

}
