/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.auth.realm.JaasSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.PublicKeyCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * Testsuite for the {@link org.wildfly.security.auth.realm.JaasSecurityRealm}.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
// has dependency on wildfly-elytron-auth-server, wildfly-elytron-realm, wildfly-elytron-credential
public class JaasSecurityRealmTest {

    @BeforeClass
    public static void beforeClass() {
        System.setProperty("java.security.auth.login.config", JaasSecurityRealmTest.class.getResource("jaas-login.config").toString());
    }

    @AfterClass
    public static void afterClass() {
        System.clearProperty("java.security.auth.login.config");
    }

    @Test
    public void testSmokeJaasSecurityRealm() throws Exception {

        // create a JAAS security realm with the file from system property and default callback handler.
        SecurityRealm realm = new JaasSecurityRealm("Entry1");

        // test the creation of a realm identity.
        RealmIdentity realmIdentity = realm.getRealmIdentity(new NamePrincipal("elytron"));
        assertNotNull("Unexpected null realm identity", realmIdentity);

        // we do not allow to obtain the credentials from the JAAS realm
        assertEquals("Invalid credential support", SupportLevel.UNSUPPORTED, realmIdentity.getCredentialAcquireSupport(PasswordCredential.class, "blah", null));
        assertEquals("Invalid credential support", SupportLevel.UNSUPPORTED,
                realmIdentity.getCredentialAcquireSupport(PublicKeyCredential.class, null, null));

        // we do not know what type of evidence the custom realms support so the result should be possibly supported
        assertEquals("Invalid credential support", SupportLevel.POSSIBLY_SUPPORTED, realmIdentity.getEvidenceVerifySupport(PasswordGuessEvidence.class, "blah"));

        // the JAAS realm identity cannot be used to obtain credentials, so getCredential should always return null.
        assertNull("Invalid non null credential", realmIdentity.getCredential(PasswordCredential.class, null));

        // use the realm identity to verify provided credentials - this will trigger a JAAS login that will use the test module.
        assertTrue(realmIdentity.verifyEvidence(new PasswordGuessEvidence("passwd12#$".toCharArray())));
        assertFalse(realmIdentity.verifyEvidence(new PasswordGuessEvidence("wrongpass".toCharArray())));

        // get the authenticated realm identity after successfully verifying the credential.
        assertTrue(realmIdentity.verifyEvidence(new PasswordGuessEvidence("passwd12#$".toCharArray())));
        assertNotNull("Unexpected null authenticated realm identity", realmIdentity.getAuthorizationIdentity());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEntryCannotBeNull() {
        new JaasSecurityRealm(null);
    }

    @Test(expected = RealmUnavailableException.class)
    public void testPathMustExist() throws RealmUnavailableException {
        JaasSecurityRealm realm = new JaasSecurityRealm("entry", "this/path/does/not/exist");
        RealmIdentity realmIdentity = realm.getRealmIdentity(new NamePrincipal("javajoe"));
        realmIdentity.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray()));
    }

    @Test
    public void testJaasSecurityRealmWithCustomCallbackHandler() throws Exception {

        // create a JAAS realm that takes a custom callback handler.
        SecurityRealm realm = new JaasSecurityRealm("Entry1", null, null, new TestCallbackHandler());
        // create a new realm identity using the realm.
        RealmIdentity realmIdentity = realm.getRealmIdentity(new NamePrincipal("javajoe"));
        // verify the credentials using the custom callback handler.
        assertTrue(realmIdentity.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray())));
        assertFalse(realmIdentity.verifyEvidence(new PasswordGuessEvidence("wrongpass".toCharArray())));
    }

    @Test
    public void testJaasSecurityRealmWithEntry2() throws Exception {

        // create a JAAS realm that takes a custom callback handler.
        SecurityRealm realm = new JaasSecurityRealm("Entry2", null, null, new TestCallbackHandler());
        // create a new realm identity using the realm.
        RealmIdentity realmIdentity = realm.getRealmIdentity(new NamePrincipal("javajoe"));
        // verify the credentials using the custom callback handler.
        assertFalse(realmIdentity.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray())));
        assertFalse(realmIdentity.verifyEvidence(new PasswordGuessEvidence("wrongpass".toCharArray())));


        realmIdentity = realm.getRealmIdentity(new NamePrincipal("userFromTestModule2"));
        // verify the credentials using the custom callback handler.
        assertFalse(realmIdentity.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray())));
        assertTrue(realmIdentity.verifyEvidence(new PasswordGuessEvidence("userPassword".toCharArray())));
    }

    @Test
    public void testJaasSecurityRealmWithConfiguredPathToJAASConfigFile() throws Exception {

        SecurityRealm realm = new JaasSecurityRealm("Entry1", "./src/test/resources/org/wildfly/security/auth/jaas-login2.config", null);
        RealmIdentity realmIdentity = realm.getRealmIdentity(new NamePrincipal("javajoe"));
        assertFalse(realmIdentity.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray())));

        realmIdentity = realm.getRealmIdentity(new NamePrincipal("userFromTestModule2"));
        assertFalse(realmIdentity.verifyEvidence(new PasswordGuessEvidence("wrongpass".toCharArray())));
        assertTrue(realmIdentity.verifyEvidence(new PasswordGuessEvidence("userPassword".toCharArray())));

        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", realm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        ServerAuthenticationContext sac1 = securityDomain.createNewAuthenticationContext();
        sac1.setAuthenticationName("userFromTestModule2");
        assertFalse(sac1.verifyEvidence(new PasswordGuessEvidence("incorrectPassword".toCharArray())));
        assertTrue(sac1.verifyEvidence(new PasswordGuessEvidence("userPassword".toCharArray())));
        Assert.assertTrue(sac1.authorize());
        Assert.assertTrue(sac1.exists());
    }

    @Test
    public void testJaasAuthorizationIdentityRoles() throws Exception { // is in role
        SecurityRealm realm = new JaasSecurityRealm("Entry1", null, null, new TestCallbackHandler());
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", realm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        ServerAuthenticationContext sac1 = securityDomain.createNewAuthenticationContext();
        sac1.setAuthenticationPrincipal(new NamePrincipal("javajoe"));
        assertTrue(sac1.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray())));
        Assert.assertTrue(sac1.authorize());
        Assert.assertTrue(sac1.exists());
        Assert.assertTrue(sac1.getAuthorizedIdentity().getRoles().contains("Admin"));
        Assert.assertTrue(sac1.getAuthorizedIdentity().getRoles().contains("User"));
        Assert.assertTrue(sac1.getAuthorizedIdentity().getRoles().contains("Guest"));
        Assert.assertFalse(sac1.getAuthorizedIdentity().getRoles().contains("Non_existent_role"));
    }

    @Test
    public void testJaasRealmAttributes() throws Exception {
        SecurityRealm realm = new JaasSecurityRealm("Entry1", null, null, new TestCallbackHandler());
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", realm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        ServerAuthenticationContext sac1 = securityDomain.createNewAuthenticationContext();
        sac1.setAuthenticationPrincipal(new NamePrincipal("javajoe"));
        assertTrue(sac1.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray())));
        Assert.assertTrue(sac1.authorize());
        Assert.assertTrue(sac1.exists());
        Assert.assertTrue(sac1.getAuthorizedIdentity().getAttributes().containsKey("NamePrincipal"));
        Assert.assertEquals("whoami", sac1.getAuthorizedIdentity().getAttributes().get("NamePrincipal").get(0));
        Assert.assertEquals("anonymous", sac1.getAuthorizedIdentity().getAttributes().get("AnonymousPrincipal").get(0));
        Assert.assertNotEquals("non_existent_attribute", sac1.getAuthorizedIdentity().getAttributes().get("NamePrincipal").get(0));
        Assert.assertNotEquals("whoami", sac1.getAuthorizedIdentity().getAttributes().get("NonExistentAttributeKey").get(0));
        Assert.assertEquals("Admin", sac1.getAuthorizedIdentity().getAttributes().get("Roles").get(0));
        Assert.assertEquals("User", sac1.getAuthorizedIdentity().getAttributes().get("Roles").get(1));
        Assert.assertEquals("Guest", sac1.getAuthorizedIdentity().getAttributes().get("Roles").get(2));
    }

    @Test
    public void testJaasRealmWithProvidedClassLoader() throws Exception {
        SecurityRealm realm = new JaasSecurityRealm("Entry1", null, TestLoginModule2.class.getClassLoader());
        SecurityDomain domainWithRewriter = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", realm).build()
                .setPermissionMapper(((permissionMappable, roles) -> LoginPermission.getInstance()))
                .build();
        ServerAuthenticationContext sac1 = domainWithRewriter.createNewAuthenticationContext();
        sac1.setAuthenticationPrincipal(new NamePrincipal("javajoe"));
        assertTrue(sac1.verifyEvidence(new PasswordGuessEvidence("$#21pass".toCharArray())));
        Assert.assertTrue(sac1.authorize());
        Assert.assertTrue(sac1.exists());
        Assert.assertTrue(sac1.getAuthorizedIdentity().getAttributes().containsKey("NamePrincipal"));
        Assert.assertEquals("whoami", sac1.getAuthorizedIdentity().getAttributes().get("NamePrincipal").get(0));
        Assert.assertEquals("anonymous", sac1.getAuthorizedIdentity().getAttributes().get("AnonymousPrincipal").get(0));
        Assert.assertNotEquals("non_existent_attribute", sac1.getAuthorizedIdentity().getAttributes().get("NamePrincipal").get(0));
        Assert.assertNotEquals("whoami", sac1.getAuthorizedIdentity().getAttributes().get("NonExistentAttributeKey").get(0));
        Assert.assertEquals("Admin", sac1.getAuthorizedIdentity().getAttributes().get("Roles").get(0));
        Assert.assertEquals("User", sac1.getAuthorizedIdentity().getAttributes().get("Roles").get(1));
        Assert.assertEquals("Guest", sac1.getAuthorizedIdentity().getAttributes().get("Roles").get(2));
    }
}
