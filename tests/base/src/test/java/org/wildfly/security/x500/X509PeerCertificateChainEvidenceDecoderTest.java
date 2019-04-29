/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.EvidenceDecoder;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.auth.util.RegexNameRewriter;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.x500.cert.SubjectAlternativeNamesExtension;
import org.wildfly.security.x500.cert.X509CertificateBuilder;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;
import org.wildfly.security.x500.principal.X500SubjectEvidenceDecoder;
import org.wildfly.security.x500.principal.X509SubjectAltNameEvidenceDecoder;

/**
 * Tests for the {@code X509PeerCertificateChainEvidence} evidence decoders.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class X509PeerCertificateChainEvidenceDecoderTest {

    @Test
    public void testDecodeX500Subject() throws Exception {
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        X500SubjectEvidenceDecoder decoder = new X500SubjectEvidenceDecoder();
        assertEquals("CN=bob0", decoder.getPrincipal(evidence).getName());
    }

    @Test
    public void testDecodeX509SubjectAltName() throws Exception {
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        X509SubjectAltNameEvidenceDecoder decoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.DNS_NAME);
        assertEquals("bob0.example.com", decoder.getPrincipal(evidence).getName());

        decoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.RFC_822_NAME);
        assertEquals("bob0@example.com", decoder.getPrincipal(evidence).getName());

        // include segment
        decoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.RFC_822_NAME, 1);
        assertEquals("bob0@anotherexample.com", decoder.getPrincipal(evidence).getName());

        // non-existent alt name
        decoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.DIRECTORY_NAME, 1);
        assertEquals(null, decoder.getPrincipal(evidence));
    }

    @Test
    public void testAggregateDecoder() throws Exception {
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain());
        X509SubjectAltNameEvidenceDecoder dnsDecoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.RFC_822_NAME, 1);
        X509SubjectAltNameEvidenceDecoder directoryNameDecoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.DIRECTORY_NAME);
        X500SubjectEvidenceDecoder subjectDecoder = new X500SubjectEvidenceDecoder();

        EvidenceDecoder aggregateDecoder = EvidenceDecoder.aggregate(directoryNameDecoder, subjectDecoder, dnsDecoder);
        assertEquals("CN=bob0", aggregateDecoder.getPrincipal(evidence).getName());

        aggregateDecoder = EvidenceDecoder.aggregate(directoryNameDecoder, dnsDecoder, subjectDecoder);
        assertEquals("bob0@anotherexample.com", aggregateDecoder.getPrincipal(evidence).getName());

        aggregateDecoder = EvidenceDecoder.aggregate(directoryNameDecoder);
        assertEquals(null, aggregateDecoder.getPrincipal(evidence));
    }

    @Test
    public void testDecodeWrongEvidenceType() {
        X509SubjectAltNameEvidenceDecoder dnsDecoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.RFC_822_NAME, 1);
        PasswordGuessEvidence passwordGuessEvidence = new PasswordGuessEvidence("secret".toCharArray());
        assertEquals(null, dnsDecoder.getPrincipal(passwordGuessEvidence));
    }

    @Test
    public void testEvidenceDecoderWithRewriting() throws Exception {
        X509SubjectAltNameEvidenceDecoder dnsDecoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.RFC_822_NAME, 1);
        X509SubjectAltNameEvidenceDecoder directoryNameDecoder = new X509SubjectAltNameEvidenceDecoder(GeneralName.DIRECTORY_NAME);
        X500SubjectEvidenceDecoder subjectDecoder = new X500SubjectEvidenceDecoder();
        EvidenceDecoder aggregateDecoder = EvidenceDecoder.aggregate(directoryNameDecoder, dnsDecoder, subjectDecoder);

        PrincipalDecoder cnDecoder = new X500AttributePrincipalDecoder("2.5.4.3");
        RegexNameRewriter cnValueRegex = new RegexNameRewriter(Pattern.compile(".*([0-9]+)$"), "$1", true);
        RegexNameRewriter dnsRegex = new RegexNameRewriter(Pattern.compile("(.*)@.*\\.com"), "$1", true);

        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> roles.contains("Admin") ? LoginPermission.getInstance() : PermissionVerifier.NONE)
                .setEvidenceDecoder(aggregateDecoder)
                .setPrincipalDecoder(cnDecoder)
                .setPreRealmRewriter(NameRewriter.chain(cnValueRegex, dnsRegex))
                .build();

        // evidence will be decoded using a subject alt name
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain(true ));
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        assertFalse(sac.verifyEvidence(evidence)); // file system security realm can't verify X509PeerCertificateChainEvidence

        sac.setDecodedEvidencePrincipal(evidence);
        assertEquals("bob0@anotherexample.com", evidence.getDecodedPrincipal().getName());
        sac.setAuthenticationPrincipal(evidence.getDecodedPrincipal());
        assertEquals("bob0", sac.getAuthenticationPrincipal().getName());
        assertFalse(sac.authorize()); // "bob0" does not have Admin role

        // evidence will be decoded using the subject
        evidence = new X509PeerCertificateChainEvidence(populateCertificateChain(false));
        sac = securityDomain.createNewAuthenticationContext();
        assertFalse(sac.verifyEvidence(evidence)); // file system security realm can't verify X509PeerCertificateChainEvidence

        sac.setDecodedEvidencePrincipal(evidence);
        assertEquals("CN=bob0", evidence.getDecodedPrincipal().getName());
        sac.setAuthenticationPrincipal(evidence.getDecodedPrincipal());
        assertEquals("0", sac.getAuthenticationPrincipal().getName());
        assertTrue(sac.authorize()); // "0" does have Admin role
    }

    @Test
    public void testDefaultEvidenceDecoder() throws Exception {
        PrincipalDecoder cnDecoder = new X500AttributePrincipalDecoder("2.5.4.3");
        RegexNameRewriter cnValueRegex = new RegexNameRewriter(Pattern.compile(".*([0-9]+)$"), "$1", true);

        FileSystemSecurityRealm fileSystemSecurityRealm = createSecurityRealm();
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", fileSystemSecurityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> roles.contains("Admin") ? LoginPermission.getInstance() : PermissionVerifier.NONE)
                .setPrincipalDecoder(cnDecoder)
                .setPreRealmRewriter(NameRewriter.chain(cnValueRegex))
                .build();

        // evidence will be decoded using the subject
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(populateCertificateChain(false));
        assertFalse(sac.verifyEvidence(evidence)); // file system security realm can't verify X509PeerCertificateChainEvidence

        sac.setDecodedEvidencePrincipal(evidence);
        assertEquals("CN=bob0", evidence.getDecodedPrincipal().getName());
        sac.setAuthenticationPrincipal(evidence.getDecodedPrincipal());
        assertEquals("0", sac.getAuthenticationPrincipal().getName());
        assertTrue(sac.authorize()); // "0" does have Admin role
    }

    private static X509Certificate[] populateCertificateChain() throws Exception {
        return populateCertificateChain(true);
    }

    private static X509Certificate[] populateCertificateChain(boolean includeSubjectAltNames) throws Exception {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        }
        final KeyPair[] keyPairs = new KeyPair[5];
        for (int i = 0; i < keyPairs.length; i++) {
            keyPairs[i] = keyPairGenerator.generateKeyPair();
        }
        final X509Certificate[] orderedCertificates = new X509Certificate[5];
        for (int i = 0; i < orderedCertificates.length; i++) {
            X509CertificateBuilder builder = new X509CertificateBuilder();
            X500PrincipalBuilder principalBuilder = new X500PrincipalBuilder();
            principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME,
                    ASN1Encodable.ofUtf8String("bob" + i)));
            X500Principal dn = principalBuilder.build();
            builder.setSubjectDn(dn);
            if (i == orderedCertificates.length - 1) {
                // self-signed
                builder.setIssuerDn(dn);
                builder.setSigningKey(keyPairs[i].getPrivate());
            } else {
                principalBuilder = new X500PrincipalBuilder();
                principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME,
                        ASN1Encodable.ofUtf8String("bob" + (i + 1))));
                X500Principal issuerDn = principalBuilder.build();
                builder.setIssuerDn(issuerDn);
                builder.setSigningKey(keyPairs[i + 1].getPrivate());
                if (includeSubjectAltNames) {
                    builder.addExtension(new SubjectAlternativeNamesExtension(
                            true,
                            Arrays.asList(new GeneralName.RFC822Name("bob" + i + "@example.com"),
                                    new GeneralName.DNSName("bob" + i + ".example.com"),
                                    new GeneralName.RFC822Name("bob" + i + "@anotherexample.com"))));
                }
            }
            builder.setSignatureAlgorithmName("SHA256withRSA");
            builder.setPublicKey(keyPairs[i].getPublic());
            orderedCertificates[i] = builder.build();
        }
        return orderedCertificates;
    }

    private FileSystemSecurityRealm createSecurityRealm() throws Exception {
        FileSystemSecurityRealm realm = new FileSystemSecurityRealm(getRootPath(true));
        addUser(realm, "0", "Admin");
        addUser(realm, "bob0", "Employee");
        return realm;
    }

    private Path getRootPath(boolean deleteIfExists) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI())
                .resolve("filesystem-realm");

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

    private Path getRootPath() throws Exception {
        return getRootPath(true);
    }

    private void addUser(ModifiableSecurityRealm realm, String userName, String roles) throws RealmUnavailableException {
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));

        ModifiableRealmIdentity realmIdentity = realm.getRealmIdentityForUpdate(new NamePrincipal(userName));
        realmIdentity.create();
        realmIdentity.setAttributes(attributes);
        realmIdentity.dispose();
    }
}
