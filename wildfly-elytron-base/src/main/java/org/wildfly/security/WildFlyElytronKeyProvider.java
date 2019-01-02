/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
import java.util.Collections;

import org.kohsuke.MetaInfServices;

/**
 * Provider for key implementations.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronKeyProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 9151849738027143961L;
    private static WildFlyElytronKeyProvider INSTANCE = new WildFlyElytronKeyProvider();

    /**
     * Construct a new instance.
     */
    private WildFlyElytronKeyProvider() {
        super("WildFlyElytronKeyProvider", "1.0", "WildFly Elytron Key Provider");
        putService(new Service(this, "SecretKeyFactory", "1.2.840.113549.1.7.1", "org.wildfly.security.key.RawSecretKeyFactory", Collections.emptyList(), Collections.emptyMap()));

    }

    /**
     * Get the key implementations provider instance.
     *
     * @return the key implementations provider instance
     */
    public static WildFlyElytronKeyProvider getInstance() {
        return INSTANCE;
    }

}
