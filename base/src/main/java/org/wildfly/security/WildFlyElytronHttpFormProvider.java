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
 * Provider for the HTTP FORM authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @deprecated Use org.wildfly.security.http.form.WildFlyElytronHttpFormProvider instead
 */
@Deprecated
@MetaInfServices(Provider.class)
public final class WildFlyElytronHttpFormProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 3872696509387755963L;
    private static WildFlyElytronHttpFormProvider INSTANCE = new WildFlyElytronHttpFormProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronHttpFormProvider() {
        super("WildFlyElytronHttpFormProvider", "1.0", "WildFly Elytron HTTP FORM Provider");
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "FORM", "org.wildfly.security.http.form.FormMechanismFactory", emptyList, emptyMap, true, true));
    }

    /**
     * Get the HTTP FORM authentication mechanism provider instance.
     *
     * @return the HTTP FORM authentication mechanism provider instance
     */
    public static WildFlyElytronHttpFormProvider getInstance() {
        return INSTANCE;
    }

}
