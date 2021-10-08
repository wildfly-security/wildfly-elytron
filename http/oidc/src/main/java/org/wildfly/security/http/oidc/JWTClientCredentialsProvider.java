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
import static org.wildfly.security.http.oidc.Oidc.PROTOCOL_CLASSPATH;
import static org.wildfly.security.http.oidc.Oidc.asInt;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.kohsuke.MetaInfServices;

/**
 * Client authentication based on JWT signed by client private key.
 * See <a href="https://tools.ietf.org/html/rfc7519">specs</a> for more details.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(value = ClientCredentialsProvider.class)
public class JWTClientCredentialsProvider implements ClientCredentialsProvider {

    private KeyPair keyPair;
    private PublicJsonWebKey publicKeyJwk;
    private int tokenTimeout;

    @Override
    public String getId() {
        return Oidc.ClientCredentialsProviderType.JWT.getValue();
    }

    public void setupKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
        if (! (keyPair.getPublic() instanceof RSAPublicKey)) {
            throw log.unsupportedPublicKey();
        }
        this.publicKeyJwk = new RsaJsonWebKey((RSAPublicKey)keyPair.getPublic());
    }

    public void setTokenTimeout(int tokenTimeout) {
        this.tokenTimeout = tokenTimeout;
    }

    protected int getTokenTimeout() {
        return tokenTimeout;
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    @Override
    public void init(OidcClientConfiguration oidcClientConfiguration, Object credentialsConfig) {
        if (!(credentialsConfig instanceof Map)) {
            throw log.invalidJwtClientCredentialsConfig(oidcClientConfiguration.getResourceName());
        }

        Map<String, Object> cfg = (Map<String, Object>) credentialsConfig;
        String clientKeyStoreFile =  (String) cfg.get("client-keystore-file");
        if (clientKeyStoreFile == null) {
            throw log.missingParameterInJwtClientCredentialsConfig("client-keystore-file", oidcClientConfiguration.getResourceName());
        }

        String clientKeyStoreType = (String) cfg.get("client-keystore-type");
        if (clientKeyStoreType == null) {
            clientKeyStoreFile = "JKS";
        }

        String clientKeyStorePassword =  (String) cfg.get("client-keystore-password");
        if (clientKeyStorePassword == null) {
            throw log.missingParameterInJwtClientCredentialsConfig("client-keystore-password", oidcClientConfiguration.getResourceName());
        }

        String clientKeyPassword = (String) cfg.get("client-key-password");
        if (clientKeyPassword == null) {
            clientKeyPassword = clientKeyStorePassword;
        }

        String clientKeyAlias =  (String) cfg.get("client-key-alias");
        if (clientKeyAlias == null) {
            clientKeyAlias = oidcClientConfiguration.getResourceName();
        }

        KeyPair keyPair = loadKeyPairFromKeyStore(clientKeyStoreFile, clientKeyStorePassword, clientKeyPassword, clientKeyAlias, clientKeyStoreType);
        setupKeyPair(keyPair);
        this.tokenTimeout = asInt(cfg, "token-timeout", 10);
    }

    @Override
    public void setClientCredentials(OidcClientConfiguration oidcClientConfiguration, Map<String, String> requestHeaders,
                                     Map<String, String> formParams) {
        String signedToken = createSignedRequestToken(oidcClientConfiguration.getResourceName(), oidcClientConfiguration.getTokenUrl());
        formParams.put(CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_JWT);
        formParams.put(CLIENT_ASSERTION, signedToken);
    }

    public String createSignedRequestToken(String clientId, String tokenUrl) {
        JwtClaims jwtClaims = createRequestToken(clientId, tokenUrl);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKeyIdHeaderValue(publicKeyJwk.getKeyId());
        jws.setKey(keyPair.getPrivate());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload(jwtClaims.toJson());
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw log.unableToCreateSignedToken();
        }
    }

    protected JwtClaims createRequestToken(String clientId, String tokenUrl) {
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

    private static KeyPair loadKeyPairFromKeyStore(String keyStoreFile, String storePassword, String keyPassword, String keyAlias, String keyStoreType) {
        InputStream stream = findFile(keyStoreFile);
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(stream, storePassword.toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
            if (privateKey == null) {
                log.unableToLoadKeyWithAlias(keyAlias);
            }
            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw log.unableToLoadPrivateKey(e);
        }
    }

    private static InputStream findFile(String keystoreFile) {
        if (keystoreFile.startsWith(PROTOCOL_CLASSPATH)) {
            String classPathLocation = keystoreFile.replace(PROTOCOL_CLASSPATH, "");
            // try current class classloader first
            InputStream is = JWTClientCredentialsProvider.class.getClassLoader().getResourceAsStream(classPathLocation);
            if (is == null) {
                is = Thread.currentThread().getContextClassLoader().getResourceAsStream(classPathLocation);
            }
            if (is != null) {
                return is;
            } else {
                throw log.unableToFindKeystoreFile(keystoreFile);
            }
        } else {
            try {
                // fallback to file
                return new FileInputStream(keystoreFile);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
