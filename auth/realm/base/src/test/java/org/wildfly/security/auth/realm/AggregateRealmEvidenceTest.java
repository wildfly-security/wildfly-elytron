/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.realm;

import java.io.File;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.FileVisitResult;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.SimpleFileVisitor;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.X509Certificate;

import java.util.Locale;
import java.util.function.Function;

import javax.security.auth.x500.X500Principal;

import org.junit.Assert;
import org.junit.Test;

import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.X500AttributeTypeAndValue;
import org.wildfly.security.x500.X500PrincipalBuilder;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

/**
 * Test case testing the {@link AggregateSecurityRealm} implementation.
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */
public class AggregateRealmEvidenceTest {
    private static final String IDENTITY_NAME = "CN=bob0";
    private static final String IDENTITY_NAME_TRANSFORMED = "CN=BOB0";
    private static final Principal IDENTITY_PRINCIPAL = new NamePrincipal(IDENTITY_NAME);
    private static final Principal IDENTITY_PRINCIPAL_TRANSFORMED = new NamePrincipal(IDENTITY_NAME_TRANSFORMED);


    /*
     * The intent of this test case is to focus on the realm aggregation aspect, the AggregateAttributesTest focuses
     * on different permutations of actual attribute aggregation. This test focuses on using evidence to obtain the identity,
     * the AggregateRealmTest focuses on using a principal to obtain the identity.
     */

    @Test
    public void testAuthenticationOnly() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        evidence.setDecodedPrincipal(IDENTITY_PRINCIPAL);

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes, null, new Attributes[] { null });
        RealmIdentity identity = testRealm.getRealmIdentity(evidence);

        Assert.assertTrue("Identity exists", identity.exists());

        // Assert no authorization attributes exist
        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        Assert.assertEquals("Expected attribute count.", 0, identityAttributes.size());
    }

    @Test
    public void testAuthorizationOnly() throws Exception {
        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "One");

        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        evidence.setDecodedPrincipal(IDENTITY_PRINCIPAL);

        SecurityRealm testRealm = createSecurityRealm(false, null, null, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(evidence);

        // Assert no identity exists as no authentication identity was added
        Assert.assertFalse("Identity does not exist", identity.exists());

        Attributes identityAttributes = identity.getAttributes();
        Assert.assertNull("No attributes expected", identityAttributes);
    }

    @Test
    public void testSingleAuthorization() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "Two");

        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        evidence.setDecodedPrincipal(IDENTITY_PRINCIPAL);

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes, null, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(evidence);

        Assert.assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        Assert.assertEquals("Expected attribute count.", 1, identityAttributes.size());
        Assert.assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
    }

    @Test
    public void testCommonRealm() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationOne = new MapAttributes();
        authorizationOne.add("team", 0, "Two");

        Attributes authorizationTwo = new MapAttributes();
        authorizationTwo.add("team", 0, "Three");
        authorizationTwo.add("office", 0, "B");

        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        evidence.setDecodedPrincipal(IDENTITY_PRINCIPAL);

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes, null, authorizationOne, authenticationAttributes, authorizationTwo);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        Assert.assertTrue("Identity exists", identity.exists());

        // Assert authorization attributes common to authentication attributes were used
        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        Assert.assertEquals("Expected attribute count.", 2, identityAttributes.size());
        Assert.assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
        Assert.assertEquals("Expected office", "A", identityAttributes.get("office", 0));
    }

    @Test
    public void testAuthenticationOnlyWithPrincipalTransformer() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");

        Function<Principal, Principal> principalTransformer = new AggregateRealmEvidenceTest.CaseRewriter().asPrincipalRewriter();
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        evidence.setDecodedPrincipal(IDENTITY_PRINCIPAL);

        SecurityRealm testRealm = createSecurityRealm(true, authenticationAttributes, principalTransformer, new Attributes[] { null });
        RealmIdentity identity = testRealm.getRealmIdentity(evidence);

        Assert.assertTrue("Identity exists", identity.exists());

        // Assert no authorization attributes exist
        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        Assert.assertEquals("Expected attribute count.", 0, identityAttributes.size());
    }

    @Test
    public void testAuthorizationOnlyWithPrincipalTransformer() throws Exception {
        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "One");

        Function<Principal, Principal> principalTransformer = new AggregateRealmEvidenceTest.CaseRewriter().asPrincipalRewriter();
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        evidence.setDecodedPrincipal(IDENTITY_PRINCIPAL);

        SecurityRealm testRealm = createSecurityRealm(true, null, principalTransformer, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(evidence);

        // Assert no identity exists as no authentication identity was added
        Assert.assertFalse("Identity does not exist", identity.exists());

        Attributes identityAttributes = identity.getAttributes();
        Assert.assertNull("No attributes expected", identityAttributes);
    }

    @Test
    public void testSingleAuthorizationWithPrincipalTransformer() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "Two");

        Function<Principal, Principal> principalTransformer = new AggregateRealmEvidenceTest.CaseRewriter().asPrincipalRewriter();
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        evidence.setDecodedPrincipal(IDENTITY_PRINCIPAL);

        SecurityRealm testRealm = createSecurityRealm(true, authenticationAttributes, principalTransformer, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(evidence);

        Assert.assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        Assert.assertEquals("Expected attribute count.", 1, identityAttributes.size());
        Assert.assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
    }

    private SecurityRealm createSecurityRealm(boolean applyPrincipalTransformer,Attributes authentication, Function<Principal, Principal> principalTransformer, Attributes... authorization)  throws Exception {
        SecurityRealm authenticationRealm = toSecurityRealm(authentication, "authentication", IDENTITY_PRINCIPAL);
        SecurityRealm[] authorizationRealms = new SecurityRealm[authorization.length];
        for (int i = 0; i < authorizationRealms.length; i++) {
            if (authentication == authorization[i]) {
                authorizationRealms[i] = authenticationRealm;
            } else {
                authorizationRealms[i] = applyPrincipalTransformer ? toSecurityRealm(authorization[i], "authorization"+String.valueOf(i), IDENTITY_PRINCIPAL_TRANSFORMED) : toSecurityRealm(authorization[i], "authorization"+String.valueOf(i), IDENTITY_PRINCIPAL);
            }
        }

        return new AggregateSecurityRealm(authenticationRealm, principalTransformer, authorizationRealms);
    }

    private SecurityRealm toSecurityRealm(Attributes attributes, String path, Principal principal) throws Exception {
        SecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(path, true));
        ModifiableRealmIdentity realmIdentity;

        if(attributes != null) {
            realmIdentity = ((FileSystemSecurityRealm) securityRealm).getRealmIdentityForUpdate(principal);
            realmIdentity.create();
            realmIdentity.setAttributes(attributes);
            realmIdentity.dispose();
            return securityRealm;
        }
        return securityRealm;
    }

    /*
     * Function to convert string to all caps
     */
    private class CaseRewriter implements NameRewriter {
        public String rewriteName(String original) {
            return (original == null) ? null : original.toUpperCase(Locale.ROOT);
        }
    }

    private static X509Certificate populateCertificateChain() throws Exception {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509CertificateBuilder builder = new X509CertificateBuilder();
        X500PrincipalBuilder principalBuilder = new X500PrincipalBuilder();
        principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME,
                ASN1Encodable.ofUtf8String("bob0")));
        X500Principal dn = principalBuilder.build();
        builder.setSubjectDn(dn);
        // self-signed
        builder.setIssuerDn(dn);
        builder.setSigningKey(keyPair.getPrivate());

        builder.setSignatureAlgorithmName("SHA256withRSA");
        builder.setPublicKey(keyPair.getPublic());
        final X509Certificate orderedCertificate = builder.build();
        return orderedCertificate;
    }

    private Path getRootPath(String path, boolean deleteIfExists) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI())
                .resolve("filesystem-realm-"+path);

        if (rootPath.toFile().exists() && !deleteIfExists) {
            return rootPath;
        }

        return Files.walkFileTree(Files.createDirectories(rootPath), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

}
