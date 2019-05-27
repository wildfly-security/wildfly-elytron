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
import java.util.Collections;

import org.kohsuke.MetaInfServices;

/**
 * Provider for Digest implementations.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @deprecated Use org.wildfly.security.digest.WildFlyElytronDigestProvider instead
 */
@Deprecated
@MetaInfServices(Provider.class)
public final class WildFlyElytronDigestProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 2531323760912222262L;
    private static WildFlyElytronDigestProvider INSTANCE = new WildFlyElytronDigestProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronDigestProvider() {
        super("WildFlyElytronDigestProvider", "1.0", "WildFly Elytron Digest Provider");
        putService(new Service(this, "MessageDigest", "SHA-512-256", "org.wildfly.security.digest.SHA512_256MessageDigest", Collections.emptyList(), Collections.emptyMap()));
    }

    /**
     * Get the Digest implementations provider instance.
     *
     * @return the Digest implementations provider instance
     */
    public static WildFlyElytronDigestProvider getInstance() {
        return INSTANCE;
    }

}
