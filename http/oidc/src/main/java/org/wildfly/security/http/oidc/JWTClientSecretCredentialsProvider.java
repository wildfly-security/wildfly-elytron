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
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ASSERTION;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ASSERTION_TYPE;
import static org.wildfly.security.http.oidc.Oidc.CLIENT_ASSERTION_TYPE_JWT;
import static org.wildfly.security.http.oidc.Oidc.asInt;
import static org.wildfly.security.http.oidc.Oidc.getJavaAlgorithm;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.kohsuke.MetaInfServices;

/**
 * Client authentication based on JWT signed by a client secret instead of a private key.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(value = ClientCredentialsProvider.class)
public class JWTClientSecretCredentialsProvider implements ClientSecretCredentialsProvider {

    private SecretKey clientSecret;
    private String clientSecretJwtAlg;
    private int tokenTimeout;

    @Override
    public String getId() {
        return Oidc.ClientCredentialsProviderType.SECRET_JWT.getValue();
    }

    public void setTokenTimeout(int tokenTimeout) {
        this.tokenTimeout = tokenTimeout;
    }

    protected int getTokenTimeout() {
        return tokenTimeout;
    }

    @Override
    public void init(OidcClientConfiguration oidcClientConfiguration, Object credentialsConfig) {
        if (!(credentialsConfig instanceof Map)) {
            throw log.invalidJwtClientCredentialsUsingSecretConfig(oidcClientConfiguration.getResourceName());
        }

        Map<String, Object> cfg = (Map<String, Object>) credentialsConfig;
        String clientSecretString = (String) cfg.get("secret");
        if (clientSecretString == null) {
            throw log.missingParameterInJwtClientCredentialsConfig("secret", oidcClientConfiguration.getResourceName());
        }

        String clientSecretJwtAlg = (String) cfg.get("algorithm");
        if (clientSecretJwtAlg == null) {
            setClientSecret(clientSecretString);
        } else if (isValidClientSecretJwtAlg(clientSecretJwtAlg)) {
            setClientSecret(clientSecretString, clientSecretJwtAlg);
        } else {
            throw log.invalidAlgorithmInJwtClientCredentialsConfig(oidcClientConfiguration.getResourceName());
        }
        this.tokenTimeout = asInt(cfg, "token-timeout", 10);
    }

    private boolean isValidClientSecretJwtAlg(String clientSecretJwtAlg) {
        boolean valid = false;
        if (AlgorithmIdentifiers.HMAC_SHA256.equals(clientSecretJwtAlg) || AlgorithmIdentifiers.HMAC_SHA384.equals(clientSecretJwtAlg)
                || AlgorithmIdentifiers.HMAC_SHA512.equals(clientSecretJwtAlg)) {
            valid = true;
        }
        return valid;
    }

    @Override
    public void setClientCredentials(OidcClientConfiguration oidcClientConfiguration, Map<String, String> requestHeaders, Map<String, String> formParams) {
        String signedToken = createSignedRequestToken(oidcClientConfiguration.getResourceName(), oidcClientConfiguration.getTokenUrl());
        formParams.put(CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_JWT);
        formParams.put(CLIENT_ASSERTION, signedToken);
    }

    @Override
    public SecretKey getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecretString) {
        setClientSecret(clientSecretString, AlgorithmIdentifiers.HMAC_SHA256);
    }

    public void setClientSecret(String clientSecretString, String algorithm) {
        // the HMAC is calculated using the octets of the UTF-8 representation of the client_secret
        clientSecret = new SecretKeySpec(clientSecretString.getBytes(StandardCharsets.UTF_8), getJavaAlgorithm(algorithm));
        clientSecretJwtAlg = algorithm;
    }

    public String createSignedRequestToken(String clientId, String tokenUrl) {
        return createSignedRequestToken(clientId, tokenUrl, clientSecretJwtAlg);
    }

    public String createSignedRequestToken(String clientId, String tokenUrl, String algorithm) {
        JwtClaims jwtClaims = createRequestToken(clientId, tokenUrl);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(clientSecret);
        jws.setAlgorithmHeaderValue(clientSecretJwtAlg);
        jws.setPayload(jwtClaims.toJson());
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw log.unableToCreateSignedToken();
        }
    }

    private JwtClaims createRequestToken(String clientId, String tokenUrl) {
        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setJwtId(Oidc.generateId());
        jwtClaims.setIssuer(clientId);
        jwtClaims.setSubject(clientId);
        jwtClaims.setAudience(tokenUrl);
        NumericDate now = NumericDate.now();
        jwtClaims.setIssuedAt(now);
        jwtClaims.setNotBefore(now);
        NumericDate exp = NumericDate.fromSeconds(now.getValue() + tokenTimeout);
        jwtClaims.setExpirationTime(exp);
        return jwtClaims;
    }
}
