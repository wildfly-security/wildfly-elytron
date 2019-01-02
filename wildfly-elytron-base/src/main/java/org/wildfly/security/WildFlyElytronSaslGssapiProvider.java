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
 * Provider for the GSSAPI SASL authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronSaslGssapiProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -6699910210685053829L;
    private static WildFlyElytronSaslGssapiProvider INSTANCE = new WildFlyElytronSaslGssapiProvider();

    /**
     * Construct a new instance.
     */
    private WildFlyElytronSaslGssapiProvider() {
        super("WildFlyElytronSaslGssapiProvider", "1.0", "WildFly Elytron SASL GSSAPI Provider");
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "GSSAPI",  "org.wildfly.security.sasl.gssapi.GssapiServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "GSSAPI",  "org.wildfly.security.sasl.gssapi.GssapiClientFactory", emptyList, emptyMap));
    }

    /**
     * Get the GSSAPI SASL authentication mechanism provider instance.
     *
     * @return the GSSAPI SASL authentication mechanism provider instance
     */
    public static WildFlyElytronSaslGssapiProvider getInstance() {
        return INSTANCE;
    }

}
