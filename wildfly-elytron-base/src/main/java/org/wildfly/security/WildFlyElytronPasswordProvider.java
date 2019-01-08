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
 * Provider for password implementations.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronPasswordProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -5105900301936981709L;
    private static WildFlyElytronPasswordProvider INSTANCE = new WildFlyElytronPasswordProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronPasswordProvider() {
        super("WildFlyElytronPasswordProvider", "1.0", "WildFly Elytron Password Provider");
        putPasswordImplementations();
        putAlgorithmParametersImplementations();
        putService(new Service(this, "MessageDigest", "SHA-512-256", "org.wildfly.security.digest.SHA512_256MessageDigest", Collections.emptyList(), Collections.emptyMap()));
    }

    /**
     * Get the password implementations provider instance.
     *
     * @return the password implementations provider instance
     */
    public static WildFlyElytronPasswordProvider getInstance() {
        return INSTANCE;
    }

}
