/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.oidc;

import java.security.Provider;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.WildFlyElytronBaseProvider;

/**
 * Provider for the HTTP OpenID Connect authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.14.0
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronHttpOidcProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -6752586426217310094L;

    private static WildFlyElytronHttpOidcProvider INSTANCE = new WildFlyElytronHttpOidcProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronHttpOidcProvider() {
        super("WildFlyElytronOidcProvider", "1.0", "WildFly Elytron HTTP OIDC Provider");
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "OIDC", "org.wildfly.security.http.oidc.OidcMechanismFactory", emptyList, emptyMap, true, true));
    }

    /**
     * Get the HTTP OIDC authentication mechanism provider instance.
     *
     * @return the HTTP OIDC authentication mechanism provider instance
     */
    public static WildFlyElytronHttpOidcProvider getInstance() {
        return INSTANCE;
    }

}
