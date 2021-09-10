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

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ClientCredentialsProviderUtils {

    public static ClientCredentialsProvider bootstrapClientAuthenticator(OidcClientConfiguration oidcClientConfiguration) {
        String clientId = oidcClientConfiguration.getResourceName();
        Map<String, Object> clientCredentials = oidcClientConfiguration.getResourceCredentials();

        String authenticatorId;
        if (clientCredentials == null || clientCredentials.isEmpty()) {
            authenticatorId = Oidc.ClientCredentialsProviderType.SECRET.getValue();
        } else {
            authenticatorId = (String) clientCredentials.get("provider");
            if (authenticatorId == null) {
                // if there is just one credential type, use its provider
                if (clientCredentials.size() == 1) {
                    authenticatorId = clientCredentials.keySet().iterator().next();
                } else {
                    throw log.unableToDetermineClientCredentialsProviderType(oidcClientConfiguration.getResourceName());
                }
            }
        }
        log.debugf("Using provider '%s' for authentication of client '%s'", authenticatorId, clientId);

        Map<String, ClientCredentialsProvider> authenticators = new HashMap<>();
        loadAuthenticators(authenticators, ClientCredentialsProviderUtils.class.getClassLoader());
        loadAuthenticators(authenticators, Thread.currentThread().getContextClassLoader());

        ClientCredentialsProvider authenticator = authenticators.get(authenticatorId);
        if (authenticator == null) {
            throw log.unableToFindClientCredentialsProvider(authenticatorId);
        }

        Object config = (clientCredentials==null) ? null : clientCredentials.get(authenticatorId);
        authenticator.init(oidcClientConfiguration, config);
        return authenticator;
    }

    private static void loadAuthenticators(Map<String, ClientCredentialsProvider> authenticators, ClassLoader classLoader) {
        Iterator<ClientCredentialsProvider> iterator = ServiceLoader.load(ClientCredentialsProvider.class, classLoader).iterator();
        while (iterator.hasNext()) {
            try {
                ClientCredentialsProvider authenticator = iterator.next();
                log.debugf("Loaded clientCredentialsProvider %s", authenticator.getId());
                authenticators.put(authenticator.getId(), authenticator);
            } catch (ServiceConfigurationError e) {
                log.debugf("Failed to load clientCredentialsProvider with classloader: " + classLoader, e);
            }
        }
    }

    /**
     * Use this method when calling backchannel request directly from your application.
     */
    public static void setClientCredentials(OidcClientConfiguration oidcClientConfiguration, Map<String, String> requestHeaders, Map<String, String> formparams) {
        ClientCredentialsProvider authenticator = oidcClientConfiguration.getClientAuthenticator();
        authenticator.setClientCredentials(oidcClientConfiguration, requestHeaders, formparams);
    }

    /**
     * Don't use directly from your apps to avoid HttpClient linkage errors! Instead use the method {@link #setClientCredentials(OidcClientConfiguration, Map, Map)}
     */
    public static void setClientCredentials(OidcClientConfiguration oidcClientConfiguration, HttpPost post, List<NameValuePair> formparams) {
        Map<String, String> reqHeaders = new HashMap<>();
        Map<String, String> reqParams = new HashMap<>();
        setClientCredentials(oidcClientConfiguration, reqHeaders, reqParams);

        for (Map.Entry<String, String> header : reqHeaders.entrySet()) {
            post.setHeader(header.getKey(), header.getValue());
        }

        for (Map.Entry<String, String> param : reqParams.entrySet()) {
            formparams.add(new BasicNameValuePair(param.getKey(), param.getValue()));
        }
    }

}
