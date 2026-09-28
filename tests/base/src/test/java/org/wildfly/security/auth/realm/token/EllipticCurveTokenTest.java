package org.wildfly.security.auth.realm.token;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.JWSAlgorithm;

import static org.wildfly.security.realm.token.test.util.JwtTestUtil.createJwt;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.evidence.EllipticCurveTokenEvidence;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.pem.Pem;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Test Elliptical Curve signing code.
 */
public class EllipticCurveTokenTest {

    @Test
    public void testNimbusdsSignatureES256Test() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();
        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
            .principalClaimName("sub")
            .validator(JwtValidator.builder()
                .issuer("elytron-oauth2-realm")
                .audience("my-app-valid")
                .publicKey(publicKeyPem.toArray()).build())
            .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(
            new EllipticCurveTokenEvidence(createJwt(new ECDSASigner(keyPair.getPrivate(), Curve.P_256),
                JWSAlgorithm.ES256, 10, -1, null, null)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testNimbusdsSignatureES384Test() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();
        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
            .principalClaimName("sub")
            .validator(JwtValidator.builder()
                .issuer("elytron-oauth2-realm")
                .audience("my-app-valid")
                .publicKey(publicKeyPem.toArray()).build())
            .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(
            new EllipticCurveTokenEvidence(createJwt(new ECDSASigner(keyPair.getPrivate(), Curve.P_384),
                JWSAlgorithm.ES384, 10, -1, null, null)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testNimbusdsSignatureES521Test() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();
        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
            .principalClaimName("sub")
            .validator(JwtValidator.builder()
                .issuer("elytron-oauth2-realm")
                .audience("my-app-valid")
                .publicKey(publicKeyPem.toArray()).build())
            .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(
            new EllipticCurveTokenEvidence(createJwt(new ECDSASigner(keyPair.getPrivate(), Curve.P_521),
                JWSAlgorithm.ES512, 10, -1, null, null)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }
}
