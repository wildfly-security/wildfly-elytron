/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import static org.jose4j.jws.AlgorithmIdentifiers.NONE;
import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.OAUTH2;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.REQUEST;
import static org.wildfly.security.http.oidc.Oidc.AuthenticationRequestFormat.REQUEST_URI;
import static org.wildfly.security.http.oidc.Oidc.SSLRequired;
import static org.wildfly.security.http.oidc.Oidc.TokenStore;
import static org.wildfly.security.http.oidc.Oidc.LOGOUT_PATH;
import static org.wildfly.security.http.oidc.Oidc.LOGOUT_CALLBACK_PATH;
import static org.wildfly.security.http.oidc.Oidc.POST_LOGOUT_PATH;
import static org.wildfly.security.http.oidc.Oidc.LOGOUT_SESSION_REQUIRED;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.concurrent.Callable;

import org.apache.http.client.HttpClient;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.jose.util.SystemPropertiesJsonParserFactory;
import org.wildfly.security.pem.Pem;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Builder for the OpenID Connect (OIDC) configuration for a client application. This class is based on
 * {@code org.keycloak.adapters.KeycloakDeploymentBuilder}.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:brad.culley@spartasystems.com">Brad Culley</a>
 * @author <a href="mailto:john.ament@spartasystems.com">John D. Ament</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcClientConfigurationBuilder {

    protected OidcClientConfiguration oidcClientConfiguration = new OidcClientConfiguration();

    protected OidcClientConfigurationBuilder() {
    }


    protected OidcClientConfiguration internalBuild(final OidcJsonConfiguration oidcJsonConfiguration) {
        if (oidcJsonConfiguration.getAuthServerUrl() != null && oidcJsonConfiguration.getRealm() == null) {
            throw log.keycloakRealmMissing();
        }
        if (oidcJsonConfiguration.getRealm() != null) {
            oidcClientConfiguration.setRealm(oidcJsonConfiguration.getRealm());
        }
        String resource = oidcJsonConfiguration.getResource();
        String clientId = oidcJsonConfiguration.getClientId();
        if (resource == null && clientId == null) {
            throw log.resourceOrClientIdMustBeSet();
        }
        oidcClientConfiguration.setResource(resource);
        oidcClientConfiguration.setClientId(clientId);

        String realmKeyPem = oidcJsonConfiguration.getRealmKey();
        if (realmKeyPem != null) {
            PublicKey realmKey;
            try {
                realmKey = Pem.parsePemPublicKey(CodePointIterator.ofString(realmKeyPem));
                HardcodedPublicKeyLocator pkLocator = new HardcodedPublicKeyLocator(realmKey);
                oidcClientConfiguration.setPublicKeyLocator(pkLocator);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            JWKPublicKeyLocator pkLocator = new JWKPublicKeyLocator();
            oidcClientConfiguration.setPublicKeyLocator(pkLocator);
        }

        if (oidcJsonConfiguration.getSslRequired() != null) {
            oidcClientConfiguration.setSSLRequired(SSLRequired.valueOf(oidcJsonConfiguration.getSslRequired().toUpperCase()));
        } else {
            oidcClientConfiguration.setSSLRequired(SSLRequired.EXTERNAL);
        }

        if (oidcJsonConfiguration.getConfidentialPort() != -1) {
            oidcClientConfiguration.setConfidentialPort(oidcJsonConfiguration.getConfidentialPort());
        }

        if (oidcJsonConfiguration.getTokenStore() != null) {
            oidcClientConfiguration.setTokenStore(TokenStore.valueOf(oidcJsonConfiguration.getTokenStore().toUpperCase()));
        } else {
            oidcClientConfiguration.setTokenStore(TokenStore.SESSION);
        }
        if (oidcJsonConfiguration.getTokenCookiePath() != null) {
            oidcClientConfiguration.setOidcStateCookiePath(oidcJsonConfiguration.getTokenCookiePath());
        }
        if (oidcJsonConfiguration.getScope() != null) {
            oidcClientConfiguration.setScope(oidcJsonConfiguration.getScope());
        }
        if (oidcJsonConfiguration.getAuthenticationRequestFormat() != null) {
            if (!(oidcJsonConfiguration.getAuthenticationRequestFormat().equals(OAUTH2.getValue()) ||
            oidcJsonConfiguration.getAuthenticationRequestFormat().equals(REQUEST.getValue()) ||
            oidcJsonConfiguration.getAuthenticationRequestFormat().equals(REQUEST_URI.getValue()))) {
                throw log.invalidAuthenticationRequestFormat();
            }
            oidcClientConfiguration.setAuthenticationRequestFormat(oidcJsonConfiguration.getAuthenticationRequestFormat());
        } else {
            oidcClientConfiguration.setAuthenticationRequestFormat(OAUTH2.getValue());
        }
        if (oidcJsonConfiguration.getRequestObjectSigningAlgorithm() != null) {
            oidcClientConfiguration.setRequestObjectSigningAlgorithm(oidcJsonConfiguration.getRequestObjectSigningAlgorithm());
        } else {
            oidcClientConfiguration.setRequestObjectSigningAlgorithm(NONE);
        }
        if (oidcJsonConfiguration.getRequestObjectEncryptionAlgValue() != null && oidcJsonConfiguration.getRequestObjectEncryptionEncValue() != null) { //both are required to encrypt the request object
            oidcClientConfiguration.setRequestObjectEncryptionAlgValue(oidcJsonConfiguration.getRequestObjectEncryptionAlgValue());
            oidcClientConfiguration.setRequestObjectEncryptionEncValue(oidcJsonConfiguration.getRequestObjectEncryptionEncValue());
            JWKEncPublicKeyLocator encryptionPublicKeyLocator = new JWKEncPublicKeyLocator();
            oidcClientConfiguration.setEncryptionPublicKeyLocator(encryptionPublicKeyLocator);
        } else if (oidcJsonConfiguration.getRequestObjectEncryptionAlgValue() != null || oidcJsonConfiguration.getRequestObjectEncryptionEncValue() != null) {   //if only one is specified, that is not correct
            throw log.invalidRequestObjectEncryptionAlgorithmConfiguration();
        }
        if (oidcJsonConfiguration.getRequestObjectSigningKeyStoreFile() != null
                && oidcJsonConfiguration.getRequestObjectSigningKeyStorePassword() != null
                && oidcJsonConfiguration.getRequestObjectSigningKeyPassword() != null
                && oidcJsonConfiguration.getRequestObjectSigningKeyAlias() != null) {
            oidcClientConfiguration.setRequestObjectSigningKeyStoreFile(oidcJsonConfiguration.getRequestObjectSigningKeyStoreFile());
            oidcClientConfiguration.setRequestObjectSigningKeyStorePassword(oidcJsonConfiguration.getRequestObjectSigningKeyStorePassword());
            oidcClientConfiguration.setRequestObjectSigningKeyPassword(oidcJsonConfiguration.getRequestObjectSigningKeyPassword());
            oidcClientConfiguration.setRequestObjectSigningKeyAlias(oidcJsonConfiguration.getRequestObjectSigningKeyAlias());
            if (oidcJsonConfiguration.getRequestObjectSigningKeyStoreType() != null) {
                oidcClientConfiguration.setRequestObjectSigningKeyStoreType(oidcJsonConfiguration.getRequestObjectSigningKeyStoreType());
            }
        }
        if (oidcJsonConfiguration.getPrincipalAttribute() != null) oidcClientConfiguration.setPrincipalAttribute(oidcJsonConfiguration.getPrincipalAttribute());

        oidcClientConfiguration.setResourceCredentials(oidcJsonConfiguration.getCredentials());
        oidcClientConfiguration.setClientAuthenticator(ClientCredentialsProviderUtils.bootstrapClientAuthenticator(oidcClientConfiguration));

        oidcClientConfiguration.setPublicClient(oidcJsonConfiguration.isPublicClient());
        oidcClientConfiguration.setUseResourceRoleMappings(oidcJsonConfiguration.isUseResourceRoleMappings());
        oidcClientConfiguration.setUseRealmRoleMappings(oidcJsonConfiguration.isUseRealmRoleMappings());

        oidcClientConfiguration.setExposeToken(oidcJsonConfiguration.isExposeToken());

        if (oidcJsonConfiguration.isCors()) {
            oidcClientConfiguration.setCors(true);
            oidcClientConfiguration.setCorsMaxAge(oidcJsonConfiguration.getCorsMaxAge());
            oidcClientConfiguration.setCorsAllowedHeaders(oidcJsonConfiguration.getCorsAllowedHeaders());
            oidcClientConfiguration.setCorsAllowedMethods(oidcJsonConfiguration.getCorsAllowedMethods());
            oidcClientConfiguration.setCorsExposedHeaders(oidcJsonConfiguration.getCorsExposedHeaders());
        }

        // https://tools.ietf.org/html/rfc7636
        if (oidcJsonConfiguration.isPkce()) {
            oidcClientConfiguration.setPkce(true);
        }

        oidcClientConfiguration.setBearerOnly(oidcJsonConfiguration.isBearerOnly());
        oidcClientConfiguration.setAutodetectBearerOnly(oidcJsonConfiguration.isAutodetectBearerOnly());
        oidcClientConfiguration.setEnableBasicAuth(oidcJsonConfiguration.isEnableBasicAuth());
        oidcClientConfiguration.setAlwaysRefreshToken(oidcJsonConfiguration.isAlwaysRefreshToken());
        oidcClientConfiguration.setRegisterNodeAtStartup(oidcJsonConfiguration.isRegisterNodeAtStartup());
        oidcClientConfiguration.setRegisterNodePeriod(oidcJsonConfiguration.getRegisterNodePeriod());
        oidcClientConfiguration.setTokenMinimumTimeToLive(oidcJsonConfiguration.getTokenMinimumTimeToLive());
        oidcClientConfiguration.setMinTimeBetweenJwksRequests(oidcJsonConfiguration.getMinTimeBetweenJwksRequests());
        oidcClientConfiguration.setPublicKeyCacheTtl(oidcJsonConfiguration.getPublicKeyCacheTtl());
        oidcClientConfiguration.setIgnoreOAuthQueryParameter(oidcJsonConfiguration.isIgnoreOAuthQueryParameter());
        oidcClientConfiguration.setRewriteRedirectRules(oidcJsonConfiguration.getRedirectRewriteRules());
        oidcClientConfiguration.setVerifyTokenAudience(oidcJsonConfiguration.isVerifyTokenAudience());

        if (realmKeyPem == null && oidcJsonConfiguration.isBearerOnly()
                && (oidcJsonConfiguration.getAuthServerUrl() == null && oidcJsonConfiguration.getProviderUrl() == null)) {
            throw log.invalidConfigurationForBearerAuth();
        }
        if ((oidcJsonConfiguration.getAuthServerUrl() == null && oidcJsonConfiguration.getProviderUrl() == null) && (!oidcClientConfiguration.isBearerOnly() || realmKeyPem == null)) {
            throw log.authServerUrlOrProviderUrlMustBeSet();
        }
        oidcClientConfiguration.setClient(createHttpClientProducer(oidcJsonConfiguration));
        oidcClientConfiguration.setAuthServerBaseUrl(oidcJsonConfiguration);
        oidcClientConfiguration.setProviderUrl(oidcJsonConfiguration.getProviderUrl());
        if (oidcJsonConfiguration.getTurnOffChangeSessionIdOnLogin() != null) {
            oidcClientConfiguration.setTurnOffChangeSessionIdOnLogin(oidcJsonConfiguration.getTurnOffChangeSessionIdOnLogin());
        }

        oidcClientConfiguration.setTokenSignatureAlgorithm(oidcJsonConfiguration.getTokenSignatureAlgorithm());

        String tmpLogoutPath = System.getProperty(LOGOUT_PATH);
        if (tmpLogoutPath != null) {
            if (isValidPath(tmpLogoutPath)) {
                oidcClientConfiguration.setLogoutPath(tmpLogoutPath);
            } else {
                throw log.invalidLogoutPath(tmpLogoutPath, LOGOUT_PATH);
            }
        }


        String tmpLogoutCallbackPath = System.getProperty(LOGOUT_CALLBACK_PATH);
        if (tmpLogoutCallbackPath != null) {
            if (isValidPath(tmpLogoutCallbackPath)
                    && !tmpLogoutCallbackPath.endsWith(oidcClientConfiguration.getLogoutPath())) {
                oidcClientConfiguration.setLogoutCallbackPath(tmpLogoutCallbackPath);
            } else {
                if (!isValidPath(tmpLogoutCallbackPath)) {
                    throw log.invalidLogoutPath(tmpLogoutPath, LOGOUT_CALLBACK_PATH);
                } else {
                    throw log.invalidLogoutCallbackPath(LOGOUT_CALLBACK_PATH, tmpLogoutCallbackPath,
                            LOGOUT_PATH, oidcClientConfiguration.getLogoutPath());
                }
            }
        }

        String tmpPostLogoutPath = System.getProperty(POST_LOGOUT_PATH);
        if (tmpPostLogoutPath != null) {
            if (isValidPath(tmpPostLogoutPath)) {
                oidcClientConfiguration.setPostLogoutPath(tmpPostLogoutPath);
            } else {
                throw log.invalidLogoutPath(tmpLogoutPath, POST_LOGOUT_PATH);
            }
        }

        String tmpLogoutSessionRequired = System.getProperty(LOGOUT_SESSION_REQUIRED);
        if (tmpLogoutSessionRequired != null) {
            oidcClientConfiguration.setLogoutSessionRequired(
                    Boolean.valueOf(tmpLogoutSessionRequired));
        }

        return oidcClientConfiguration;
    }

    private Callable<HttpClient> createHttpClientProducer(final OidcJsonConfiguration oidcJsonConfiguration) {
        return new Callable<HttpClient>() {
            private HttpClient client;
            @Override
            public HttpClient call() {
                if (client == null) {
                    synchronized (oidcClientConfiguration) {
                        if (client == null) {
                            client = new HttpClientBuilder().build(oidcJsonConfiguration);
                        }
                    }
                }
                return client;
            }
        };
    }

    public static OidcClientConfiguration build(InputStream is) {
        OidcJsonConfiguration oidcJsonConfiguration = loadOidcJsonConfiguration(is);
        return new OidcClientConfigurationBuilder().internalBuild(oidcJsonConfiguration);
    }

    public static OidcJsonConfiguration loadOidcJsonConfiguration(InputStream is) {
        ObjectMapper mapper = new ObjectMapper(new SystemPropertiesJsonParserFactory());
        mapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);
        OidcJsonConfiguration adapterConfig;
        try {
            adapterConfig = mapper.readValue(is, OidcJsonConfiguration.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return adapterConfig;
    }

    public static OidcClientConfiguration build(OidcJsonConfiguration oidcJsonConfiguration) {
        return new OidcClientConfigurationBuilder().internalBuild(oidcJsonConfiguration);
    }

    private boolean isValidPath(String path) {
        String tmpPath = path.trim();
        if (tmpPath.length() > 1 && tmpPath.startsWith("/")) {
            return true;
        }
        return false;
    }
}
