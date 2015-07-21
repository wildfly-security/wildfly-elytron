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

import javax.security.sasl.SaslServerFactory;

import org.wildfly.common.Assert;
import org.wildfly.security.sasl.util.FilterMechanismSaslServerFactory;

/**
 * A SASL server factory configuration.  The configuration is associated with a security domain, and also includes a
 * SASL server factory which may be {@linkplain FilterMechanismSaslServerFactory pre-configured} to enforce a specific policy.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityDomainSaslConfiguration {
    private final SecurityDomain securityDomain;
    private final SaslServerFactory saslServerFactory;

    /**
     * Construct a new instance.
     *
     * @param securityDomain the security domain
     * @param saslServerFactory the (optionally pre-configured) SASL server factory
     */
    public SecurityDomainSaslConfiguration(final SecurityDomain securityDomain, final SaslServerFactory saslServerFactory) {
        Assert.checkNotNullParam("securityDomain", securityDomain);
        Assert.checkNotNullParam("saslServerFactory", saslServerFactory);
        this.securityDomain = securityDomain;
        this.saslServerFactory = saslServerFactory;
    }

    /**
     * Get the security domain.
     *
     * @return the security domain
     */
    public SecurityDomain getSecurityDomain() {
        return securityDomain;
    }

    /**
     * Get the SASL server factory.
     *
     * @return the SASL server factory
     */
    public SaslServerFactory getSaslServerFactory() {
        return saslServerFactory;
    }
}
