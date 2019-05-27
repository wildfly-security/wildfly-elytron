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
 * Provider for the HTTP SPNEGO authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @deprecated use org.wildfly.security.http.spnego.WildFlyElytronHttpSpnegoProvider instead
 */
@Deprecated
@MetaInfServices(Provider.class)
public final class WildFlyElytronHttpSpnegoProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 9211317885580156246L;
    private static WildFlyElytronHttpSpnegoProvider INSTANCE = new WildFlyElytronHttpSpnegoProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronHttpSpnegoProvider() {
        super("WildFlyElytronHttpSpnegoProvider", "1.0", "WildFly Elytron HTTP SPNEGO Provider");
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "SPNEGO", "org.wildfly.security.http.spnego.SpnegoMechanismFactory", emptyList, emptyMap));
    }

    /**
     * Get the HTTP SPNEGO authentication mechanism provider instance.
     *
     * @return the HTTP SPNEGO authentication mechanism provider instance
     */
    public static WildFlyElytronHttpSpnegoProvider getInstance() {
        return INSTANCE;
    }

}
