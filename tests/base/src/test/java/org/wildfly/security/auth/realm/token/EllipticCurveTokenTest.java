package org.wildfly.security.auth.realm.token;

import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.JWSAlgorithm;

import static org.wildfly.security.realm.token.test.util.JwtTestUtil.createJwt;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.evidence.EllipticCurveTokenEvidence;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.realm.token.validator.OAuth2IntrospectValidator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.pem.Pem;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
        // Must pin the curve explicitly: KeyPairGenerator.getInstance("EC") without an
        // initialize() call uses the provider's default curve (P-384 on this JVM/provider),
        // not P-521 - despite the Curve.P_521/JWSAlgorithm.ES512 passed to the signer below.
        // That mismatch previously produced signature components with far fewer significant
        // bytes than a genuine P-521 signature has, which silently avoided exercising the
        // DER length-encoding bug fixed for ES512 in JwtValidator.encodeDER().
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
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

    @Test
    public void testTamperedSignatureFailsCleanly() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();
        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        String jwt = createJwt(new ECDSASigner(keyPair.getPrivate(), Curve.P_256), JWSAlgorithm.ES256, 10, -1, null, null);
        String[] parts = jwt.split("\\.", -1);
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
        signatureBytes[0] ^= 0x01; // flip a single bit in R
        String tamperedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        String tamperedJwt = parts[0] + "." + parts[1] + "." + tamperedSignature;

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
            .principalClaimName("sub")
            .validator(JwtValidator.builder()
                .issuer("elytron-oauth2-realm")
                .audience("my-app-valid")
                .publicKey(publicKeyPem.toArray()).build())
            .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new EllipticCurveTokenEvidence(tamperedJwt));
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testOddLengthP1363SignatureFailsCleanly() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();
        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        String jwt = createJwt(new ECDSASigner(keyPair.getPrivate(), Curve.P_256), JWSAlgorithm.ES256, 10, -1, null, null);
        String[] parts = jwt.split("\\.", -1);
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);
        // drop one byte so convertP1363ToDER's "length % 2 != 0" guard is hit
        byte[] oddLengthSignature = Arrays.copyOf(signatureBytes, signatureBytes.length - 1);
        String malformedJwt = parts[0] + "." + parts[1] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(oddLengthSignature);

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
            .principalClaimName("sub")
            .validator(JwtValidator.builder()
                .issuer("elytron-oauth2-realm")
                .audience("my-app-valid")
                .publicKey(publicKeyPem.toArray()).build())
            .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new EllipticCurveTokenEvidence(malformedJwt));
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testWrongEvenLengthP1363SignatureFailsCleanly() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();
        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        String jwt = createJwt(new ECDSASigner(keyPair.getPrivate(), Curve.P_256), JWSAlgorithm.ES256, 10, -1, null, null);
        String[] parts = jwt.split("\\.", -1);
        // even length, but far too short to be a genuine P-256 (64-byte) P1363 signature
        byte[] tooShortSignature = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        String malformedJwt = parts[0] + "." + parts[1] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(tooShortSignature);

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
            .principalClaimName("sub")
            .validator(JwtValidator.builder()
                .issuer("elytron-oauth2-realm")
                .audience("my-app-valid")
                .publicKey(publicKeyPem.toArray()).build())
            .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new EllipticCurveTokenEvidence(malformedJwt));
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testAlgHeaderAgainstMismatchedCurveKeyFailsCleanly() throws Exception {
        KeyPairGenerator p256Generator = KeyPairGenerator.getInstance("EC");
        p256Generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair signingKeyPair = p256Generator.generateKeyPair(); // genuinely signs the token: P-256/ES256

        KeyPairGenerator p384Generator = KeyPairGenerator.getInstance("EC");
        p384Generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair configuredKeyPair = p384Generator.generateKeyPair(); // realm is configured with an unrelated P-384 key

        String jwt = createJwt(new ECDSASigner(signingKeyPair.getPrivate(), Curve.P_256), JWSAlgorithm.ES256, 10, -1, null, null);

        ByteStringBuilder mismatchedPublicKeyPem = new ByteStringBuilder();
        Pem.generatePemPublicKey(mismatchedPublicKeyPem, configuredKeyPair.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
            .principalClaimName("sub")
            .validator(JwtValidator.builder()
                .issuer("elytron-oauth2-realm")
                .audience("my-app-valid")
                .publicKey(mismatchedPublicKeyPem.toArray()).build())
            .build();

        // Documents current behavior per claude-docs/jwks-unification/pr-integration/ELY-2929/
        // 02-pr-review.md section 2: JwtValidator does not cross-check the alg header's implied
        // curve against the actual curve of the resolved key. That is not exploitable as a forgery
        // (Signature.verify() just fails cleanly: the P-256 signature does not cryptographically
        // validate against an unrelated P-384 key), which this test confirms.
        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new EllipticCurveTokenEvidence(jwt));
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testEllipticCurveEvidenceThroughOAuth2IntrospectValidatorFailsCleanly() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        String jwt = createJwt(new ECDSASigner(keyPair.getPrivate(), Curve.P_256), JWSAlgorithm.ES256, 10, -1, null, null);

        // OAuth2IntrospectValidator has no EC verification logic at all; this must fail cleanly
        // via the public RealmIdentity.exists() API, not via a ClassCastException, and must not
        // attempt any network call (no introspection endpoint is reachable here).
        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
            .principalClaimName("sub")
            .validator(OAuth2IntrospectValidator.builder()
                .tokenIntrospectionUrl(new URL("http://localhost/unreachable-introspect"))
                .clientId("test-client")
                .clientSecret("test-secret")
                .build())
            .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new EllipticCurveTokenEvidence(jwt));
        assertFalse(realmIdentity.exists());
    }

    @Test
    public void testGetEvidenceVerifySupportVariesByConfiguredValidator() throws Exception {
        TokenSecurityRealm jwtBackedRealm = TokenSecurityRealm.builder()
            .validator(JwtValidator.builder()
                .issuer("elytron-oauth2-realm")
                .audience("my-app-valid")
                .build())
            .build();
        assertEquals(SupportLevel.POSSIBLY_SUPPORTED,
            jwtBackedRealm.getEvidenceVerifySupport(EllipticCurveTokenEvidence.class, null));

        TokenSecurityRealm oauth2BackedRealm = TokenSecurityRealm.builder()
            .validator(OAuth2IntrospectValidator.builder()
                .tokenIntrospectionUrl(new URL("http://localhost/unreachable-introspect"))
                .clientId("test-client")
                .clientSecret("test-secret")
                .build())
            .build();
        assertEquals(SupportLevel.UNSUPPORTED,
            oauth2BackedRealm.getEvidenceVerifySupport(EllipticCurveTokenEvidence.class, null));
    }
}
