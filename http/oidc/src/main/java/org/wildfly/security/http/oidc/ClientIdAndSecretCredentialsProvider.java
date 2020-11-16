/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.AUTHORIZATION;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ID;
import static org.wildfly.security.http.oidc.Oidc.getJavaAlgorithm;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.kohsuke.MetaInfServices;
import org.wildfly.common.iteration.ByteIterator;

/**
 * Traditional OAuth2 authentication of clients based on client_id and client_secret
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@MetaInfServices(value = ClientCredentialsProvider.class)
public class ClientIdAndSecretCredentialsProvider implements ClientSecretCredentialsProvider {

    private String clientSecretString;
    private SecretKey clientSecret;

    @Override
    public String getId() {
        return Oidc.ClientCredentialsProviderType.SECRET.getValue();
    }

    @Override
    public void init(OidcClientConfiguration oidcClientConfiguration, Object credentialsConfig) {
        clientSecretString = (String) credentialsConfig;
        clientSecret = credentialsConfig == null ? null : new SecretKeySpec(clientSecretString.getBytes(StandardCharsets.UTF_8), getJavaAlgorithm(AlgorithmIdentifiers.HMAC_SHA256));
    }

    @Override
    public void setClientCredentials(OidcClientConfiguration oidcClientConfiguration, Map<String, String> requestHeaders, Map<String, String> formParams) {
        String clientId = oidcClientConfiguration.getResourceName();

        if (! oidcClientConfiguration.isPublicClient()) {
            if (clientSecretString != null) {
                String authorization = createBasicHeader(clientId, clientSecretString);
                requestHeaders.put(AUTHORIZATION, authorization);
            } else {
                log.noClientSecretConfigured(clientId);
            }
        } else {
            formParams.put(CLIENT_ID, clientId);
        }
    }

    @Override
    public SecretKey getClientSecret() {
        return clientSecret;
    }

    private static String createBasicHeader(String username, String password) {
        StringBuffer buf = new StringBuffer(username);
        buf.append(':').append(password);
        return "Basic " + ByteIterator.ofBytes(buf.toString().getBytes(StandardCharsets.UTF_8)).base64Encode().drainToString();
    }
}
