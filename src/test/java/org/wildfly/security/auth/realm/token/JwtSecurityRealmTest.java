/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.realm.token;

import static org.junit.Assert.*;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.PlainObject;
import com.nimbusds.jose.crypto.RSASSASigner;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import javax.json.Json;
import javax.json.JsonObjectBuilder;
import mockit.integration.junit4.JMockit;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.sasl.test.BaseTestCase;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@RunWith(JMockit.class)
public class JwtSecurityRealmTest extends BaseTestCase {

    @Test
    public void testUsingGeneratedPublicKey() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();

        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .publicKey(publicKeyPem.toArray()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new BearerTokenEvidence(createJwt(keyPair, 10, 0)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testEmptyConfiguration() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();

        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder().build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new BearerTokenEvidence(createJwt(keyPair, 10, 0)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testWithMultipleAudience() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("third-app", "another-app-valid", "my-app")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new BearerTokenEvidence(createJwt(keyPair)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testInvalidSignature() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair));
        KeyPair anotherKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .publicKey(anotherKeyPair.getPublic()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testInvalidIssuer() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair));

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("different-issuer")
                        .audience("my-app-valid")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testInvalidAudience() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair));

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("different-audience")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testTokenExpired() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair, -1));

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("different-audience")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testTokenNotBefore() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair, 10, 10));

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("different-audience")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testUnsecuredJwt() throws Exception {
        PlainObject plainObject = new PlainObject(new PlainHeader(), new Payload(createClaims(10, 0).build().toString()));
        BearerTokenEvidence evidence = new BearerTokenEvidence(plainObject.serialize());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid").build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    private String createJwt(KeyPair keyPair, int expirationOffset) throws Exception {
        return createJwt(keyPair, expirationOffset, -1);
    }

    private String createJwt(KeyPair keyPair, int expirationOffset, int notBeforeOffset) throws Exception {
        PrivateKey privateKey = keyPair.getPrivate();
        JWSSigner signer = new RSASSASigner(privateKey);
        JsonObjectBuilder claimsBuilder = createClaims(expirationOffset, notBeforeOffset);

        JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("jwt")).build(),
                new Payload(claimsBuilder.build().toString()));

        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    private String createJwt(KeyPair keyPair) throws Exception {
        return createJwt(keyPair, 60);
    }

    private JsonObjectBuilder createClaims(int expirationOffset, int notBeforeOffset) {
        JsonObjectBuilder claimsBuilder = Json.createObjectBuilder()
                .add("active", true)
                .add("sub", "elytron@jboss.org")
                .add("iss", "elytron-oauth2-realm")
                .add("aud", Json.createArrayBuilder().add("my-app-valid").add("third-app-valid").add("another-app-valid").build())
                .add("exp", (System.currentTimeMillis() / 1000) + expirationOffset);

        if (notBeforeOffset > 0) {
            claimsBuilder.add("nbf", (System.currentTimeMillis() / 1000) + notBeforeOffset);
        }

        return claimsBuilder;
    }
}
