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

package org.wildfly.security;

import java.security.Provider;

import org.kohsuke.MetaInfServices;

/**
 * Provider for the Entity SASL authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronSaslEntityProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 498264316387776361L;
    private static WildFlyElytronSaslEntityProvider INSTANCE = new WildFlyElytronSaslEntityProvider();

    /**
     * Construct a new instance.
     */
    private WildFlyElytronSaslEntityProvider() {
        super("WildFlyElytronSaslEntityProvider", "1.0", "WildFly Elytron SASL Entity Provider");
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "9798-U-RSA-SHA1-ENC",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "9798-M-RSA-SHA1-ENC",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "9798-U-DSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "9798-M-DSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "9798-U-ECDSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "9798-M-ECDSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "9798-U-RSA-SHA1-ENC",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "9798-M-RSA-SHA1-ENC",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "9798-U-DSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "9798-M-DSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "9798-U-ECDSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "9798-M-ECDSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
    }

    /**
     * Get the Entity SASL authentication mechanism provider instance.
     *
     * @return the Entity SASL authentication mechanism provider instance
     */
    public static WildFlyElytronSaslEntityProvider getInstance() {
        return INSTANCE;
    }

}
