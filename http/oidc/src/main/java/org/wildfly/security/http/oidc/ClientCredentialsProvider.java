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

import java.util.Map;

/**
 * SPI for authenticating clients/applications. This is used during all OIDC backchannel requests to the OpenID provider
 * (codeToToken exchange, refresh token or backchannel logout). You can also use it in your application during direct
 * access grants or service account request.
 *
 * You must specify a file
 * META-INF/services/org.wildfly.security.http.oidc.ClientCredentialsProvider in the WAR that this class is contained in
 * (or in the JAR that is attached to the WEB-INF/lib or as jboss module if you want to share the implementation among more WARs).
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public interface ClientCredentialsProvider {

    /**
     * Return the ID of the provider. Use this ID in the oidc.json configuration as the sub-element of the "credentials" element
     *
     * For example if your provider has ID "some-provider", use the configuration like this in oidc.json
     *
     * "credentials": {
     *
     *     "some-provider": {
     *         "someAttribute": "someValue"
     *     }
     * }
     *
     * @return the ID of the provider
     */
    String getId();

    /**
     * Called during deployment of your application.
     *
     * @param oidcClientConfiguration the OIDC client configuration
     * @param credentialsConfig the configuration of your credentials provider read from oidc.json. For the some-provider
     *                          example above, it will return map with the single key "someAttribute" with value "someValue"
     */
    void init(OidcClientConfiguration oidcClientConfiguration, Object credentialsConfig);

    /**
     * Called every time a backchannel request is performed.
     *
     * @param oidcClientConfiguration the fully resolved OIDC client configuration
     * @param requestHeaders You should put any HTTP request headers you want to use for authentication of client.
     *                       These headers will be attached to the HTTP request sent to the OpenID provider
     * @param formParams You should put any request parameters you want to use for authentication of client.
     *                   These parameters will be attached to the HTTP request sent to the OpenID provider
     */
    void setClientCredentials(OidcClientConfiguration oidcClientConfiguration, Map<String, String> requestHeaders,
                              Map<String, String> formParams);
}
