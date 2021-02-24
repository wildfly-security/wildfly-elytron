/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.server;

import static org.wildfly.common.Assert.assertTrue;

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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.regex.Pattern;
import javax.security.auth.x500.X500Principal;
import org.junit.Test;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.AggregateSecurityRealm;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.util.RegexNameRewriter;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.X500AttributeTypeAndValue;
import org.wildfly.security.x500.X500PrincipalBuilder;
import org.wildfly.security.x500.cert.SubjectAlternativeNamesExtension;
import org.wildfly.security.x500.cert.X509CertificateBuilder;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;

/**
 * Test to verify evidence is being used in realm mapper. This test case verifies
 * behaviour reported in ELY-2090 is corrected.
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class CustomRealmMapperTest {

    private final String REALM_A = "realmA";
    private final String REALM_B = "realmB";

    @Test
    public void testEvidenceUsedInServerAuthenticationContextRealmMapping() throws Exception {
        CustomRealmMapper mapper = new CustomRealmMapper();
        X509Certificate[] chainedCertificates = populateCertificateChain();

        // The aggregate realm is the one we want to map to when evidence is not null
        KeyStoreBackedSecurityRealm authenticationRealm = createKeystoreSecurityRealm(chainedCertificates);
        FileSystemSecurityRealm authorizationRealm = createSecurityRealm(true, REALM_A);
        AggregateSecurityRealm realm = new AggregateSecurityRealm(authenticationRealm, authorizationRealm);

        // Some other realm with wrong roles we map to by default when evidence is null
        FileSystemSecurityRealm wrongRealm = createSecurityRealm(false, REALM_B);

        PrincipalDecoder cnDecoder = new X500AttributePrincipalDecoder("2.5.4.3");
        RegexNameRewriter cnValueRegex = new RegexNameRewriter(Pattern.compile(".*([0-9]+)$"), "$1", true);

        SecurityDomain securityDomain = SecurityDomain.builder()
                .addRealm(REALM_A, realm).build()
                .addRealm(REALM_B, wrongRealm).build()
                .setDefaultRealmName(REALM_B)
                .setPermissionMapper((permissionMappable, roles) -> roles.contains("Admin") ? LoginPermission.getInstance() : PermissionVerifier.NONE)
                .setRealmMapper(mapper)
                .setPrincipalDecoder(cnDecoder)
                .setPreRealmRewriter(NameRewriter.chain(cnValueRegex))
                .build();

        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(chainedCertificates);
        assertTrue(sac.verifyEvidence(evidence));

        // bob0 should only be authorized in REALM_A, which was mapped with the custom realm mapper
        assertTrue(sac.authorize());
    }

    private KeyStoreBackedSecurityRealm createKeystoreSecurityRealm(X509Certificate[] chainedCertificates) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        for (int i = 0; i < chainedCertificates.length; i++) {
            keyStore.setCertificateEntry(String.valueOf(i), chainedCertificates[i]);
        }
        return new KeyStoreBackedSecurityRealm(keyStore);
    }

    private FileSystemSecurityRealm createSecurityRealm(boolean isAdmin, String realmName) throws Exception {
        FileSystemSecurityRealm realm = new FileSystemSecurityRealm(getRootPath(true, realmName));
        if (isAdmin) {
            addUser(realm, "0", "Admin");
        } else {
            addUser(realm, "0", "Employee");
        }
        return realm;
    }

    private Path getRootPath(boolean deleteIfExists, String realmName) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI())
                .resolve("filesystem-realm/" + realmName);

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

    private void addUser(ModifiableSecurityRealm realm, String userName, String roles) throws RealmUnavailableException {
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));

        ModifiableRealmIdentity realmIdentity = realm.getRealmIdentityForUpdate(new NamePrincipal(userName));
        realmIdentity.create();
        realmIdentity.setAttributes(attributes);
        realmIdentity.dispose();
    }

    private static X509Certificate[] populateCertificateChain() throws Exception {
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
                builder.addExtension(new SubjectAlternativeNamesExtension(
                        true,
                        Arrays.asList(new GeneralName.RFC822Name("bob" + i + "@example.com"),
                                new GeneralName.DNSName("bob" + i + ".example.com"),
                                new GeneralName.RFC822Name("bob" + i + "@anotherexample.com"))));
            }
            builder.setSignatureAlgorithmName("SHA256withRSA");
            builder.setPublicKey(keyPairs[i].getPublic());
            orderedCertificates[i] = builder.build();
        }
        return orderedCertificates;
    }


    /**
     * Custom Realm Mapper which maps to a given realm depending on whether evidence is null or not.
     * ONLY for testing.
     */
    private class CustomRealmMapper implements RealmMapper {

        public CustomRealmMapper() {
        }

        @Override
        public String getRealmMapping(Principal principal, Evidence evidence) {
            return evidence != null ? REALM_A : REALM_B;
        }
    }
}
