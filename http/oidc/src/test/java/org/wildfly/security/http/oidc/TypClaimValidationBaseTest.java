/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import javax.json.Json;
import javax.json.JsonObjectBuilder;

import mockit.Mock;
import mockit.MockUp;

/**
 * Base test class for typ claim validation tests.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class TypClaimValidationBaseTest {

    public static String ISSUER_URL = "http://localhost:8080/realms/myrealm";
    public static String SUBJECT = "bf8ce366-0a74-4628-bd9a-1e69084ae558";

    /**
     * The issuerUrl gets set using OIDC discovery. Since this test class isn't
     * making use of the Keycloak OpenID provider, we are mocking the return
     * value for the issuer URL.
     */
    protected static void mockIssuerUrl(String issuerUrl) {
        Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.http.oidc.OidcClientConfiguration",
                    true, OidcClientConfiguration.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock) {
            @Mock
            public String getIssuerUrl() {
                return issuerUrl;
            }
        };
    }

    protected static AccessToken testTokenValidationWithoutTypClaim() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        HardcodedPublicKeyLocator hardcodedPublicKeyLocator = new HardcodedPublicKeyLocator(keyPair.getPublic());

        OidcClientConfiguration clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("clientWithoutTyp");
        clientConfiguration.setPublicKeyLocator(hardcodedPublicKeyLocator);
        clientConfiguration.setProviderUrl(ISSUER_URL);
        clientConfiguration.setPublicClient(true);
        clientConfiguration.setPrincipalAttribute("preferred_username");
        clientConfiguration.setSSLRequired(Oidc.SSLRequired.EXTERNAL);

        TokenValidator tokenValidator = TokenValidator.builder(clientConfiguration).build();
        return tokenValidator.parseAndVerifyToken(createJwt(keyPair, 60, "1"));
    }

    private static String createJwt(KeyPair keyPair, int expirationOffset, String kid) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        JWSSigner signer = new RSASSASigner(privateKey);
        JsonObjectBuilder claimsBuilder = createClaims(expirationOffset);

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("jwt"));
        if (kid != null) {
            headerBuilder.keyID(kid);
        }

        JWSObject jwsObject = new JWSObject(headerBuilder.build(), new Payload(claimsBuilder.build().toString()));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    private static JsonObjectBuilder createClaims(int expirationOffset) {
        // typ claim not included
        return Json.createObjectBuilder()
                .add("sub", SUBJECT)
                .add("iss", ISSUER_URL)
                .add("aud", "account")
                .add("exp", (System.currentTimeMillis() / 1000) + expirationOffset)
                .add("azp", "app")
                .add("scope", "profile email")
                .add("preferred_username", "alice");
    }

}
