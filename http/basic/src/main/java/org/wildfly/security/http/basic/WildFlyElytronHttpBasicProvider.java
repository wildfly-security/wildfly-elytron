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

package org.wildfly.security.http.basic;

import java.security.Provider;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.WildFlyElytronBaseProvider;

/**
 * Provider for the HTTP BASIC authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronHttpBasicProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 3029961619967561017L;
    private static WildFlyElytronHttpBasicProvider INSTANCE = new WildFlyElytronHttpBasicProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronHttpBasicProvider() {
        super("WildFlyElytronHttpBasicProvider", "1.0", "WildFly Elytron HTTP BASIC Provider");
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "BASIC", "org.wildfly.security.http.basic.BasicMechanismFactory", emptyList, emptyMap));
    }

    /**
     * Get the HTTP BASIC authentication mechanism provider instance.
     *
     * @return the HTTP BASIC authentication mechanism provider instance
     */
    public static WildFlyElytronHttpBasicProvider getInstance() {
        return INSTANCE;
    }

}
