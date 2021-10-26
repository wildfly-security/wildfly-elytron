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

package org.wildfly.security.auth.realm.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.auth.server.ServerUtils.ELYTRON_PASSWORD_PROVIDERS;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.Test;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.realm.CachingModifiableSecurityRealm;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableRealmIdentityIterator;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.cache.LRURealmIdentityCache;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.Encoding;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on auth-realm
public class ModifiableSecurityRealmIdentityCacheTest {

    private AtomicInteger realmHitCount = new AtomicInteger();

    @Test
    public void testInvalidateEntryAfterChangingAttributes() throws Exception {
        ModifiableSecurityRealm securityRealm = createSecurityRealm();
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", securityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        SecurityIdentity securityIdentity = assertAuthenticationAndAuthorization("joe", "password", securityDomain);

        assertTrue(securityIdentity.getAttributes().get("someAttribute").isEmpty());

        assertEquals(1, realmHitCount.get());

        ModifiableRealmIdentity joe = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("joe"));

        Attributes newAttributes = new MapAttributes();

        newAttributes.addFirst("someAttribute", "value");

        joe.setAttributes(newAttributes);
        joe.dispose();

        securityIdentity = assertAuthenticationAndAuthorization("joe", "password", securityDomain);

        assertEquals(2, realmHitCount.get());

        assertFalse(securityIdentity.getAttributes().get("someAttribute").isEmpty());
    }

    @Test
    public void testInvalidateEntryAfterChangingCredentials() throws Exception {
        ModifiableSecurityRealm securityRealm = createSecurityRealm();
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", securityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        assertAuthenticationAndAuthorization("joe", "password", securityDomain);
        assertEquals(1, realmHitCount.get());

        ModifiableRealmIdentity joe = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("joe"));
        List<Credential> credentials;

        try {
            credentials = Collections.singletonList(
                    new PasswordCredential(
                            PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS).generatePassword(
                                    new ClearPasswordSpec("password_changed".toCharArray()))));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        joe.setCredentials(credentials);
        joe.dispose();

        assertAuthenticationAndAuthorization("joe", "password_changed", securityDomain);

        assertEquals(2, realmHitCount.get());
    }

    @Test
    public void testInvalidateEntryAfterChangingCredentialsFromIterator() throws Exception {
        ModifiableSecurityRealm securityRealm = createSecurityRealm();
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", securityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        assertAuthenticationAndAuthorization("joe", "password", securityDomain);
        assertEquals(1, realmHitCount.get());

        ModifiableRealmIdentityIterator iterator = securityRealm.getRealmIdentityIterator();

        ModifiableRealmIdentity joe = iterator.next();
        List<Credential> credentials;

        try {
            credentials = Collections.singletonList(
                    new PasswordCredential(
                            PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS).generatePassword(
                                    new ClearPasswordSpec("password_changed".toCharArray()))));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        joe.setCredentials(credentials);
        joe.dispose();

        assertAuthenticationAndAuthorization("joe", "password_changed", securityDomain);

        assertEquals(2, realmHitCount.get());
    }

    private ModifiableSecurityRealm createSecurityRealm() throws Exception {
        FileSystemSecurityRealm realm = new FileSystemSecurityRealm(getRootPath(true), NameRewriter.IDENTITY_REWRITER, 2, true, Encoding.BASE64, StandardCharsets.UTF_8, ELYTRON_PASSWORD_PROVIDERS, null, null, null);

        addUser(realm, "joe", "User");

        return new CachingModifiableSecurityRealm(new MockCacheableModifiableSecurityRealm(realm), createRealmIdentitySimpleJavaMapCache(), ELYTRON_PASSWORD_PROVIDERS);
    }

    private void addUser(ModifiableSecurityRealm realm, String userName, String roles) throws RealmUnavailableException {
        List<Credential> credentials;
        try {
            credentials = Collections.singletonList(
                    new PasswordCredential(
                            PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS).generatePassword(
                                    new ClearPasswordSpec("password".toCharArray()))));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        MapAttributes attributes = new MapAttributes();

        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));

        ModifiableRealmIdentity realmIdentity = realm.getRealmIdentityForUpdate(new NamePrincipal(userName));

        realmIdentity.create();

        realmIdentity.setAttributes(attributes);
        realmIdentity.setCredentials(credentials);

        realmIdentity.dispose();
    }

    private SecurityIdentity  assertAuthenticationAndAuthorization(String username, String password, SecurityDomain securityDomain) throws Exception{
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();

        sac.setAuthenticationName(username);
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence(password.toCharArray())));
        assertTrue(sac.authorize(username));

        sac.succeed();

        SecurityIdentity securityIdentity = sac.getAuthorizedIdentity();
        assertNotNull(securityIdentity);
        assertEquals(username, securityIdentity.getPrincipal().getName());

        return securityIdentity;
    }

    private RealmIdentityCache createRealmIdentitySimpleJavaMapCache() {
        return new LRURealmIdentityCache(16);
    }

    private Path getRootPath(boolean deleteIfExists) throws Exception {
        Path rootPath = Paths.get(getClass().getResource(File.separator).toURI()).resolve("filesystem-realm-cache");
        boolean exists = rootPath.toFile().exists();

        if (exists) {
            if (!deleteIfExists) {
                return rootPath;
            }
        } else {
            rootPath = Files.createDirectory(rootPath);
        }

        return Files.walkFileTree(rootPath, new SimpleFileVisitor<Path>() {
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

    private class MockCacheableModifiableSecurityRealm implements ModifiableSecurityRealm, CacheableSecurityRealm {
        private final FileSystemSecurityRealm realm;

        public MockCacheableModifiableSecurityRealm(FileSystemSecurityRealm realm) {
            this.realm = realm;
        }

        @Override
        public void registerIdentityChangeListener(Consumer<Principal> listener) {
            realm.registerIdentityChangeListener(listener);
        }

        @Override
        public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
            realmHitCount.incrementAndGet();
            return realm.getRealmIdentity(principal);
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return realm.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            return realm.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        public ModifiableRealmIdentity getRealmIdentityForUpdate(Principal principal) throws RealmUnavailableException {
            return realm.getRealmIdentityForUpdate(principal);
        }

        @Override
        public ModifiableRealmIdentityIterator getRealmIdentityIterator() throws RealmUnavailableException {
            return realm.getRealmIdentityIterator();
        }
    }
}
