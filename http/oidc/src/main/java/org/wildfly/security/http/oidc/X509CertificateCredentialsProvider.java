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

import static org.wildfly.security.http.oidc.Oidc.CLIENT_ID;

import java.util.Map;

import org.kohsuke.MetaInfServices;

/**
 * X509 certificate authentication. This assumes the actual certificate has been configured on the client SSLContext,
 * which is done on the OIDC provider or secure-deployment.
 * <br/>
 * This class only serves as a placeholder to add the client_id argument to the body.
 */
@MetaInfServices(value = ClientCredentialsProvider.class)
public class X509CertificateCredentialsProvider implements ClientCredentialsProvider {
    @Override
    public String getId() {
        return Oidc.ClientCredentialsProviderType.X509_CERTIFICATE.getValue();
    }

    @Override
    public void init(OidcClientConfiguration oidcClientConfiguration,
                     Object credentialsConfig) {
        // Not possible to check the key/truststore configuration from here. It needs access to the
        // OidcJsonConfiguration object to check.
    }

    @Override
    public void setClientCredentials(OidcClientConfiguration oidcClientConfiguration,
                                     Map<String, String> requestHeaders,
                                     Map<String, String> formParams) {
        String clientId = oidcClientConfiguration.getResourceName();
        formParams.put(CLIENT_ID, clientId);
    }
}
