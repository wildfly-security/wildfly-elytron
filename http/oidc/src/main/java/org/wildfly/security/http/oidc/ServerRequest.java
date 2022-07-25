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
import static org.wildfly.security.http.oidc.Oidc.AUTHORIZATION_CODE;
import static org.wildfly.security.http.oidc.Oidc.CODE;
import static org.wildfly.security.http.oidc.Oidc.GRANT_TYPE;
import static org.wildfly.security.http.oidc.Oidc.KEYCLOAK_CLIENT_CLUSTER_HOST;
import static org.wildfly.security.http.oidc.Oidc.PASSWORD;
import static org.wildfly.security.http.oidc.Oidc.REDIRECT_URI;
import static org.wildfly.security.http.oidc.Oidc.USERNAME;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.wildfly.security.jose.util.JsonSerialization;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ServerRequest {

    private static final int BUFFER_LENGTH = 4096;

    public static AccessAndIDTokenResponse invokeRefresh(OidcClientConfiguration deployment, String refreshToken) throws IOException, HttpFailure {
        List<NameValuePair> formparams = new ArrayList<NameValuePair>();
        formparams.add(new BasicNameValuePair(GRANT_TYPE, Oidc.REFRESH_TOKEN));
        formparams.add(new BasicNameValuePair(Oidc.REFRESH_TOKEN, refreshToken));

        HttpPost post = new HttpPost(deployment.getTokenUrl());
        ClientCredentialsProviderUtils.setClientCredentials(deployment, post, formparams);

        UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, StandardCharsets.UTF_8);
        post.setEntity(form);
        HttpResponse response = deployment.getClient().execute(post);
        int status = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();
        if (status != 200) {
            error(status, entity);
        }
        if (entity == null) {
            throw new HttpFailure(status, null);
        }
        InputStream is = entity.getContent();
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            int c;
            while ((c = is.read()) != -1) {
                os.write(c);
            }
            byte[] bytes = os.toByteArray();
            String json = new String(bytes);
            try {
                return JsonSerialization.readValue(json, AccessAndIDTokenResponse.class);
            } catch (IOException e) {
                throw new IOException(json, e);
            }
        } finally {
            try {
                is.close();
            } catch (IOException ignored) {
            }
        }
    }

    public static void invokeLogout(OidcClientConfiguration deployment, String refreshToken) throws IOException, HttpFailure {
        HttpClient client = deployment.getClient();
        String uri = deployment.getLogoutUrl();
        List<NameValuePair> formparams = new ArrayList<>();

        formparams.add(new BasicNameValuePair(Oidc.REFRESH_TOKEN, refreshToken));
        HttpPost post = new HttpPost(uri);
        ClientCredentialsProviderUtils.setClientCredentials(deployment, post, formparams);

        UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, StandardCharsets.UTF_8);
        post.setEntity(form);
        HttpResponse response = client.execute(post);
        int status = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();
        if (status != 204) {
            error(status, entity);
        }
        if (entity == null) {
            return;
        }
        InputStream is = entity.getContent();
        if (is != null) is.close();
    }

    public static AccessAndIDTokenResponse invokeAccessCodeToToken(OidcClientConfiguration deployment, String code, String redirectUri) throws IOException, HttpFailure {
        List<NameValuePair> formparams = new ArrayList<>();
        formparams.add(new BasicNameValuePair(GRANT_TYPE, AUTHORIZATION_CODE));
        formparams.add(new BasicNameValuePair(CODE, code));
        formparams.add(new BasicNameValuePair(REDIRECT_URI, redirectUri));

        HttpPost post = new HttpPost(deployment.getTokenUrl());
        ClientCredentialsProviderUtils.setClientCredentials(deployment, post, formparams);

        UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, StandardCharsets.UTF_8);
        post.setEntity(form);
        HttpResponse response = deployment.getClient().execute(post);
        int status = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();
        if (status != HttpStatus.SC_OK) {
            error(status, entity);
        }
        if (entity == null) {
            throw new HttpFailure(status, null);
        }
        InputStream is = entity.getContent();
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            int c;
            while ((c = is.read()) != -1) {
                os.write(c);
            }
            byte[] bytes = os.toByteArray();
            String json = new String(bytes);
            try {
                return JsonSerialization.readValue(json, AccessAndIDTokenResponse.class);
            } catch (IOException e) {
                throw new IOException(json, e);
            }
        } finally {
            try {
                is.close();
            } catch (IOException ignored) {
            }
        }
    }

    public static void invokeRegisterNodeForKeycloak(OidcClientConfiguration deployment, String host) throws HttpFailure, IOException {
        String registerNodeUrl = deployment.getRegisterNodeUrl();
        invokeClientManagementRequestForKeycloak(deployment, host, registerNodeUrl);
    }

    public static void invokeUnregisterNodeForKeycloak(OidcClientConfiguration deployment, String host) throws HttpFailure, IOException {
        String unregisterNodeUrl = deployment.getUnregisterNodeUrl();
        invokeClientManagementRequestForKeycloak(deployment, host, unregisterNodeUrl);
    }

    public static void invokeClientManagementRequestForKeycloak(OidcClientConfiguration deployment, String host, String endpointUrl) throws HttpFailure, IOException {
        if (endpointUrl == null) {
            throw new IOException("You need to configure URI for register/unregister node for application " + deployment.getResourceName());
        }

        List<NameValuePair> formparams = new ArrayList<>();
        formparams.add(new BasicNameValuePair(KEYCLOAK_CLIENT_CLUSTER_HOST, host));

        HttpPost post = new HttpPost(endpointUrl);
        ClientCredentialsProviderUtils.setClientCredentials(deployment, post, formparams);

        UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
        post.setEntity(form);
        HttpResponse response = deployment.getClient().execute(post);
        int status = response.getStatusLine().getStatusCode();
        if (status != 204) {
            HttpEntity entity = response.getEntity();
            error(status, entity);
        }
    }

    public static void error(int status, HttpEntity entity) throws HttpFailure, IOException {
        String body = null;
        if (entity != null) {
            InputStream is = entity.getContent();
            try {
                body = readString(is, Charset.defaultCharset());
            } catch (IOException e) {

            } finally {
                try {
                    is.close();
                } catch (IOException ignored) {
                }
            }
        }
        throw new HttpFailure(status, body);
    }

    private static String readString(InputStream in, Charset charset) throws IOException {
        char[] buffer = new char[BUFFER_LENGTH];
        StringBuilder builder = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, charset));
        int wasRead;
        do {
            wasRead = reader.read(buffer, 0, BUFFER_LENGTH);
            if (wasRead > 0) {
                builder.append(buffer, 0, wasRead);
            }
        }
        while (wasRead > -1);
        return builder.toString();
    }

    public static class HttpFailure extends Exception {
        private int status;
        private String error;

        public HttpFailure(int status, String error) {
            this.status = status;
            this.error = error;
        }

        public int getStatus() {
            return status;
        }

        public String getError() {
            return error;
        }
    }

    public static AccessAndIDTokenResponse getBearerToken(OidcClientConfiguration oidcClientConfiguration, String username, String password) throws Exception {
        AccessAndIDTokenResponse tokenResponse;
        HttpClient client = oidcClientConfiguration.getClient();

        HttpPost post = new HttpPost(oidcClientConfiguration.getTokenUrl());
        List<NameValuePair> formparams = new ArrayList<>();
        formparams.add(new BasicNameValuePair(GRANT_TYPE, PASSWORD));
        formparams.add(new BasicNameValuePair(USERNAME, username));
        formparams.add(new BasicNameValuePair(PASSWORD, password));

        ClientCredentialsProviderUtils.setClientCredentials(oidcClientConfiguration, post, formparams);
        UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
        post.setEntity(form);

        HttpResponse response = client.execute(post);
        int status = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();
        if (status != HttpStatus.SC_OK) {
            EntityUtils.consumeQuietly(entity);
            throw log.unableToObtainToken(status);
        }
        if (entity == null) {
            throw log.noMessageEntity();
        }
        InputStream is = entity.getContent();
        try {
            tokenResponse = JsonSerialization.readValue(is, AccessAndIDTokenResponse.class);
        } finally {
            try {
                is.close();
            } catch (java.io.IOException ignored) {
            }
        }
        return tokenResponse;
    }
}
