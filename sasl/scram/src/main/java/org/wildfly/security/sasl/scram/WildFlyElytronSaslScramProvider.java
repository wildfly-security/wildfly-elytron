/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE_2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl.scram;

import java.security.Provider;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.WildFlyElytronBaseProvider;

/**
 * Provider for the SCRAM SASL authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronSaslScramProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 2647962616155165113L;
    private static WildFlyElytronSaslScramProvider INSTANCE = new WildFlyElytronSaslScramProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronSaslScramProvider() {
        super("WildFlyElytronSaslScramProvider", "1.0", "WildFly Elytron SASL SCRAM Provider");
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-512-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-384-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-256-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-1-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-512",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-384",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-256",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-1",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-512-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-384-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-256-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-1-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-512",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-384",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-256",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-1",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));

        putService(new Service(this, PASSWORD_FACTORY_TYPE, "clear", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "scram-sha-1", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "scram-sha-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "scram-sha-384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "scram-sha-512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
    }

    /**
     * Get the SCRAM SASL authentication mechanism provider instance.
     *
     * @return the SCRAM SASL authentication mechanism provider instance
     */
    public static WildFlyElytronSaslScramProvider getInstance() {
        return INSTANCE;
    }

}
