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

package org.wildfly.security;

import java.security.Provider;

import org.kohsuke.MetaInfServices;


/**
 * Provider for the External SASL authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronSaslExternalProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -8090113592399245366L;
    private static WildFlyElytronSaslExternalProvider INSTANCE = new WildFlyElytronSaslExternalProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronSaslExternalProvider() {
        super("WildFlyElytronSaslExternalProvider", "1.0", "WildFly Elytron SASL External Provider");
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "EXTERNAL",  "org.wildfly.security.sasl.external.ExternalSaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "EXTERNAL",  "org.wildfly.security.sasl.external.ExternalSaslClientFactory", emptyList, emptyMap));
    }

    /**
     * Get the External SASL authentication mechanism provider instance.
     *
     * @return the External SASL authentication mechanism provider instance
     */
    public static WildFlyElytronSaslExternalProvider getInstance() {
        return INSTANCE;
    }

}
