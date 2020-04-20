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

package org.wildfly.security.http.external;

import java.security.Provider;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.WildFlyElytronBaseProvider;

/**
 * Provider for the HTTP External authentication mechanism.
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */
@MetaInfServices(Provider.class)
public class WildFlyElytronHttpExternalProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 6923305263952210174L;
    private static WildFlyElytronHttpExternalProvider INSTANCE = new WildFlyElytronHttpExternalProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronHttpExternalProvider() {
        super("WildFlyElytronHttpExternalProvider", "1.0", "WildFly Elytron HTTP External Provider");
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "EXTERNAL", "org.wildfly.security.http.external.ExternalMechanismFactory", emptyList, emptyMap, true, true));
    }

    /**
     * Get the HTTP External authentication mechanism provider instance.
     *
     * @return the HTTP External authentication mechanism provider instance
     */
    public static WildFlyElytronHttpExternalProvider getInstance() {
        return INSTANCE;
    }

}
