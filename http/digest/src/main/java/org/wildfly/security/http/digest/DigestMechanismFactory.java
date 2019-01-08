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

package org.wildfly.security.http.digest;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.http.HttpConstants.CONFIG_CONTEXT_PATH;
import static org.wildfly.security.http.HttpConstants.CONFIG_REALM;
import static org.wildfly.security.http.HttpConstants.DIGEST_NAME;
import static org.wildfly.security.http.HttpConstants.DIGEST_SHA256_NAME;
import static org.wildfly.security.http.HttpConstants.DIGEST_SHA512_256_NAME;
import static org.wildfly.security.http.HttpConstants.MD5;
import static org.wildfly.security.http.HttpConstants.SHA256;
import static org.wildfly.security.http.HttpConstants.SHA512_256;
import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.mechanism._private.ElytronMessages;

/**
 * The {@link HttpServerAuthenticationMechanismFactory} implementation for the HTTP Digest authentication mechanism.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MetaInfServices(value = HttpServerAuthenticationMechanismFactory.class)
public class DigestMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    private final Supplier<Provider[]> providers;

    public DigestMechanismFactory() {
        providers = INSTALLED_PROVIDERS;
    }

    public DigestMechanismFactory(final Provider provider) {
        providers = () -> new Provider[] { provider };
    }

    /*
     * 5  Minutes Initial Nonce Validity
     * 15 Minutes Validity Since Last Use With Nonce Count
     * Single Use
     * 20 Byte Private Key (Gives us at least enough material for SHA-256 to digest))
     * SHA256 Digest Algorithm
     */

    private static NonceManager nonceManager = new NonceManager(300000, 900000, true, 20, SHA256, ElytronMessages.httpDigest);

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        // TODO We may cache this later but for now leave the option open for properties to influence selection.
        ArrayList<String> mechanismNames = new ArrayList<>();
        mechanismNames.add(DIGEST_NAME);
        mechanismNames.add(DIGEST_SHA256_NAME);
        mechanismNames.add(DIGEST_SHA512_256_NAME);

        return mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
        checkNotNullParam("mechanismName", mechanismName);
        checkNotNullParam("properties", properties);
        checkNotNullParam("callbackHandler", callbackHandler);

        switch (mechanismName) {                                
            case DIGEST_NAME:
                return new DigestAuthenticationMechanism(callbackHandler, nonceManager, (String) properties.get(CONFIG_REALM), (String) properties.get(CONFIG_CONTEXT_PATH), DIGEST_NAME, MD5, providers, (String) properties.get(HttpConstants.CONFIG_VALIDATE_DIGEST_URI));
            case DIGEST_SHA256_NAME:
                return new DigestAuthenticationMechanism(callbackHandler, nonceManager, (String) properties.get(CONFIG_REALM), (String) properties.get(CONFIG_CONTEXT_PATH), DIGEST_SHA256_NAME, SHA256, providers, (String) properties.get(HttpConstants.CONFIG_VALIDATE_DIGEST_URI));
            case DIGEST_SHA512_256_NAME:
                return new DigestAuthenticationMechanism(callbackHandler, nonceManager, (String) properties.get(CONFIG_REALM), (String) properties.get(CONFIG_CONTEXT_PATH), DIGEST_SHA512_256_NAME, SHA512_256, providers, (String) properties.get(HttpConstants.CONFIG_VALIDATE_DIGEST_URI));                                
        }
        return null;
    }

}
