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
 * Provider for the HTTP Bearer authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronHttpBearerProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -797775107834905210L;
    private static WildFlyElytronHttpBearerProvider INSTANCE = new WildFlyElytronHttpBearerProvider();

    /**
     * Construct a new instance.
     */
    private WildFlyElytronHttpBearerProvider() {
        super("WildFlyElytronHttpBearerProvider", "1.0", "WildFly Elytron HTTP Bearer Provider");
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "BEARER_TOKEN", "org.wildfly.security.http.bearer.BearerTokenAuthenticationMechanism", emptyList, emptyMap));
    }

    /**
     * Get the HTTP Bearer authentication mechanism provider instance.
     *
     * @return the HTTP Bearer authentication mechanism provider instance
     */
    public static WildFlyElytronHttpBearerProvider getInstance() {
        return INSTANCE;
    }

}
