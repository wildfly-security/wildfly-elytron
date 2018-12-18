/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.PrivilegedActionException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.permission.RunAsPrincipalPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Simple tests for identity switching using different runAs blocks.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
// has dependency on wildfly-elytron-realm
public class IdentitySwitchingTest {

    private static SecurityDomain usersDomain;
    private static SecurityDomain adminsDomain;

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void setup() throws Exception {
        Security.addProvider(provider);

        SimpleMapBackedSecurityRealm usersRealm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();
        addUser(users, "joe", "User");
        addUser(users, "bob", "User");
        usersRealm.setIdentityMap(users);

        SimpleMapBackedSecurityRealm adminsRealm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> admins = new HashMap<>();
        addUser(admins, "admin", "Admin");
        adminsRealm.setIdentityMap(admins);

        SecurityDomain.Builder builder = SecurityDomain.builder();
        builder.addRealm("users", usersRealm).build();
        builder.setDefaultRealmName("users");
        builder.setPermissionMapper((permissionMappable, roles) ->
                PermissionVerifier.from(new LoginPermission())
                        .or(PermissionVerifier.from(new RunAsPrincipalPermission("bob"))));
        usersDomain = builder.build();

        builder = SecurityDomain.builder();
        builder.addRealm("admins", adminsRealm).build();
        builder.setDefaultRealmName("admins");
        adminsDomain = builder.build();
    }

    @AfterClass
    public static void clean() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testRunAsBlock() throws Exception {
        SecurityIdentity anonymous = usersDomain.getAnonymousSecurityIdentity();
        SecurityIdentity joe = usersDomain.authenticate("joe", new PasswordGuessEvidence("password".toCharArray()));
        SecurityIdentity bob = anonymous.createRunAsIdentity("bob", false);
        assertEquals("joe", joe.getPrincipal().getName());

        assertEquals(anonymous, usersDomain.getCurrentSecurityIdentity());
        joe.runAs(() -> {
            assertEquals(joe.getPrincipal(), usersDomain.getCurrentSecurityIdentity().getPrincipal());
            joe.createRunAsIdentity("bob", true).runAs(() -> {
                assertEquals(bob.getPrincipal(), usersDomain.getCurrentSecurityIdentity().getPrincipal());
                joe.createRunAsAnonymous().runAs(() -> {
                    assertEquals(anonymous, usersDomain.getCurrentSecurityIdentity());
                });
                assertEquals(bob.getPrincipal(), usersDomain.getCurrentSecurityIdentity().getPrincipal());
            });
            assertEquals(joe.getPrincipal(), usersDomain.getCurrentSecurityIdentity().getPrincipal());
        });
        assertEquals(anonymous, usersDomain.getCurrentSecurityIdentity());
    }

    @Test
    public void testWithSecurityIdentity() {
        SecurityIdentity joe = usersDomain.getAnonymousSecurityIdentity().createRunAsIdentity("joe", false);
        SecurityIdentity admin = adminsDomain.getAnonymousSecurityIdentity().createRunAsIdentity("admin", false);

        joe.withSecurityIdentity(joe).withSecurityIdentity(admin).withSecurityIdentity(admin).runAs(() -> {
            assertEquals(joe.getPrincipal(), usersDomain.getCurrentSecurityIdentity().getPrincipal());
            assertEquals(admin.getPrincipal(), adminsDomain.getCurrentSecurityIdentity().getPrincipal());
        });

        assertEquals(usersDomain.getAnonymousSecurityIdentity(), usersDomain.getCurrentSecurityIdentity());
        assertEquals(adminsDomain.getAnonymousSecurityIdentity(), adminsDomain.getCurrentSecurityIdentity());
    }

    @Test
    public void testRunAsAll() throws PrivilegedActionException {
        SecurityIdentity joe = usersDomain.getAnonymousSecurityIdentity().createRunAsIdentity("joe", false);
        SecurityIdentity admin = adminsDomain.getAnonymousSecurityIdentity().createRunAsIdentity("admin", false);

        SecurityIdentity.runAsAll(() -> {
            assertEquals(joe.getPrincipal(), usersDomain.getCurrentSecurityIdentity().getPrincipal());
            assertEquals(admin.getPrincipal(), adminsDomain.getCurrentSecurityIdentity().getPrincipal());
            return Boolean.TRUE;
        }, joe, admin);

        assertEquals(usersDomain.getAnonymousSecurityIdentity(), usersDomain.getCurrentSecurityIdentity());
        assertEquals(adminsDomain.getAnonymousSecurityIdentity(), adminsDomain.getCurrentSecurityIdentity());
    }

    @Test
    public void testWithRoleMapper() {
        SecurityIdentity joe = usersDomain.getAnonymousSecurityIdentity().createRunAsIdentity("joe", false);
        SecurityIdentity joeWithRoles = joe
                .withRoleMapper("cat1", RoleMapper.constant(Roles.of("constantJoesRole")))
                .withRoleMapper("cat2", RoleMapper.constant(Roles.of("secondRole")));
        assertTrue(joeWithRoles.getRoles("cat1").contains("constantJoesRole"));
        assertTrue(joeWithRoles.getRoles("cat2").contains("secondRole"));
    }

    private static void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles) throws Exception {
        List<Credential> credentials;
        credentials = Collections.singletonList(
                new PasswordCredential(
                        PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                                new ClearPasswordSpec("password".toCharArray()))));
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));
        securityRealm.put(userName, new SimpleRealmEntry(credentials, attributes));
    }

}
