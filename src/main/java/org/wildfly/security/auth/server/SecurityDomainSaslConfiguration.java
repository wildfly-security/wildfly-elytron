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

import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.security.sasl.SaslServerFactory;

import org.wildfly.common.Assert;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.FilterMechanismSaslServerFactory;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.util._private.UnmodifiableArrayList;

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
        this.securityDomain = Assert.checkNotNullParam("securityDomain", securityDomain);
        Assert.checkNotNullParam("saslServerFactory", saslServerFactory);
        this.saslServerFactory = new FilterMechanismSaslServerFactory(saslServerFactory, name -> {
            final Set<Class<?>> credentialTypes = SaslMechanismInformation.getSupportedServerCredentialTypes(name);
            if (credentialTypes == null) {
                // unknown, just pass
                return true;
            }
            for (Class<?> credentialType : credentialTypes) {
                final Set<String> algorithms = SaslMechanismInformation.getSupportedServerCredentialAlgorithms(name, credentialType);
                if (algorithms.isEmpty()) {
                    if (! securityDomain.getCredentialSupport(credentialType, null).isNotSupported()) {
                        // some level of support exists
                        return true;
                    }
                } else for (String algorithm : algorithms) {
                    if (! securityDomain.getCredentialSupport(credentialType, algorithm).isNotSupported()) {
                        // some level of support exists
                        return true;
                    }
                }
            }
            return false;
        });
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

    /**
     * Get the list of SASL server mechanism names that are provided by the given factory and allowed by this
     * configuration.
     *
     * @return the list of mechanism names
     */
    public List<String> getMechanismNames() {
        final String[] names = saslServerFactory.getMechanismNames(Collections.singletonMap(WildFlySasl.MECHANISM_QUERY_ALL, "true"));
        // todo: filter down based on SASL selection criteria
        if (names == null || names.length == 0) {
            return Collections.emptyList();
        } else if (names.length == 1) {
            return Collections.singletonList(names[0]);
        } else {
            return new UnmodifiableArrayList<>(names);
        }
    }

}
