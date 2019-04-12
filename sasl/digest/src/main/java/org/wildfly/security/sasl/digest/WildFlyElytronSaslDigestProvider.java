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

package org.wildfly.security.sasl.digest;

import java.security.Provider;
import java.util.Collections;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.WildFlyElytronBaseProvider;

/**
 * Provider for the Digest SASL authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronSaslDigestProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 4489281716376579143L;
    private static WildFlyElytronSaslDigestProvider INSTANCE = new WildFlyElytronSaslDigestProvider();

    /**
     * Construct a new instance.
     */
    public WildFlyElytronSaslDigestProvider() {
        super("WildFlyElytronSaslDigestProvider", "1.0", "WildFly Elytron SASL Digest Provider");
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA-512",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA-512-256",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA-256",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA-384",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-MD5",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA-512",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA-512-256",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA-256",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA-384",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-MD5",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));

        putService(new Service(this, "MessageDigest", "SHA-512-256", "org.wildfly.security.digest.SHA512_256MessageDigest", Collections.emptyList(), Collections.emptyMap()));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "clear", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
    }

    /**
     * Get the Digest SASL authentication mechanism provider instance.
     *
     * @return the Digest SASL authentication mechanism provider instance
     */
    public static WildFlyElytronSaslDigestProvider getInstance() {
        return INSTANCE;
    }

}
