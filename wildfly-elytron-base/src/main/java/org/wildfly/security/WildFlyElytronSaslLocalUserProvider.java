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
 * Provider for the JBOSS-LOCAL-USER SASL authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronSaslLocalUserProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 4188534864141338518L;
    private static WildFlyElytronSaslLocalUserProvider INSTANCE = new WildFlyElytronSaslLocalUserProvider();

    /**
     * Construct a new instance.
     */
    private WildFlyElytronSaslLocalUserProvider() {
        super("WildFlyElytronSaslLocalUserProvider", "1.0", "WildFly Elytron SASL Local User Provider");
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "JBOSS-LOCAL-USER",  "org.wildfly.security.sasl.localuser.LocalUserServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "JBOSS-LOCAL-USER",  "org.wildfly.security.sasl.localuser.LocalUserClientFactory", emptyList, emptyMap));
    }

    /**
     * Get the JBOSS-LOCAL-USER SASL authentication mechanism provider instance.
     *
     * @return the JBOSS-LOCAL-USER authentication mechanism provider instance
     */
    public static WildFlyElytronSaslLocalUserProvider getInstance() {
        return INSTANCE;
    }

}
