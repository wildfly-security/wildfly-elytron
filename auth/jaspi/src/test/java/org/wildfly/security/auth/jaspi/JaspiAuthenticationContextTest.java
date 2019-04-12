/*
 * Copyright 2018 Red Hat, Inc.
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

package org.wildfly.security.auth.jaspi;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.Principal;
import java.security.Provider;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;

import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.auth.jaspi.impl.JaspiAuthenticationContext;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.PermissionMapper;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Test case testing the {@link JaspiAuthenticationContext} implementation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JaspiAuthenticationContextTest {

    private static final Attributes COMMON_ATTRIBUTES = new MapAttributes();

    private static final Provider PROVIDER = WildFlyElytronPasswordProvider.getInstance();

    private static PasswordFactory passwordFactory;
    private static SecurityDomain securityDomain;

    @BeforeClass
    public static void initialiseSecurityDomain() throws Exception {
        passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, PROVIDER);
        Map<String, SimpleRealmEntry> identityMap = new HashMap<>();
        add(identityMap, "identityOne", "passwordOne".toCharArray());
        add(identityMap, "identityTwo", "passwordTwo".toCharArray());
        add(identityMap, "identityThree", "passwordThree".toCharArray());

        SimpleMapBackedSecurityRealm mapBackedSecurityRealm = new SimpleMapBackedSecurityRealm(() -> new Provider[] { PROVIDER });
        mapBackedSecurityRealm.setIdentityMap(identityMap);

        securityDomain = SecurityDomain.builder()
                .addRealm("default", mapBackedSecurityRealm)
                    .build()
                .setDefaultRealmName("default")
                .setRoleMapper(RoleMapper.constant(Roles.of("DefaultRole")))
                .setPermissionMapper(PermissionMapper.createConstant(PermissionVerifier.from(new LoginPermission())))
                .build();
    }

    private static void add(Map<String, SimpleRealmEntry> identityMap, final String identityName, final char[] password) throws Exception {
        identityMap.put(identityName,
                new SimpleRealmEntry(
                        Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password)))),
                        COMMON_ATTRIBUTES));
    }

    /**
     * A simple authentication test validating a name and password and verifying the resulting identity.
     */
    @Test
    public void testAuthentication_Integrated() throws Exception {
        testAuthentication(true, false);
    }

    /**
     * A simple authentication test validating a name and password and verifying the resulting identity.
     */
    @Test
    public void testAuthentication_NonIntegrated() throws Exception {
        testAuthentication(false, false);
    }

    /**
     * An authentication test validating a name and password and overriding the assigned roles and verifying the resulting identity.
     */
    @Test
    public void testRoleOverride_Integrated() throws Exception {
        testAuthentication(true, true);
    }

    /**
     * An authentication test validating a name and password and overriding the assigned roles and verifying the resulting identity.
     */
    @Test
    public void testRoleOverride_NonIntegrated() throws Exception {
        testAuthentication(false, true);
    }

    private void testAuthentication(final boolean integrated, final boolean overrideRole) throws Exception {
        Subject clientSubject = new Subject();
        JaspiAuthenticationContext jaspiAuthenticationContext = JaspiAuthenticationContext.newInstance(securityDomain, integrated);
        CallbackHandler callbackHandler = jaspiAuthenticationContext.createCallbackHandler();
        PasswordValidationCallback pvc = new PasswordValidationCallback(clientSubject, "identityTwo", "passwordTwo".toCharArray());
        CallerPrincipalCallback cpc = new CallerPrincipalCallback(clientSubject, (Principal) null);

        if (overrideRole) {
            GroupPrincipalCallback gpc = new GroupPrincipalCallback(clientSubject, new String[] { "NewRole" });
            handle(callbackHandler, pvc, cpc, gpc);
        } else {
            handle(callbackHandler, pvc, cpc);
        }

        assertTrue("Password not verified", pvc.getResult());

        SecurityIdentity authorizedIdentity = jaspiAuthenticationContext.getAuthorizedIdentity();
        assertEquals("Unexpected Principal", "identityTwo", authorizedIdentity.getPrincipal().getName());
        assertTrue("Not in expected role", authorizedIdentity.getRoles().contains(overrideRole ? "NewRole" : "DefaultRole"));
        assertFalse("In unexpected role", authorizedIdentity.getRoles().contains(overrideRole ? "DefaultRole" : "NewRole"));
    }

    /**
     * A simple authentication test validating an incorrect password is correctly rejected.
     */
    @Test
    public void testFailedAuthentication_Integrated() throws Exception {
        testFailedAuthentication(true);
    }

    /**
     * A simple authentication test validating an incorrect password is correctly rejected.
     */
    @Test
    public void testFailedAuthentication_NonIntegrated() throws Exception {
        testFailedAuthentication(false);
    }

    private void testFailedAuthentication(final boolean integrated) throws Exception {
        Subject clientSubject = new Subject();
        JaspiAuthenticationContext jaspiAuthenticationContext = JaspiAuthenticationContext.newInstance(securityDomain, integrated);
        CallbackHandler callbackHandler = jaspiAuthenticationContext.createCallbackHandler();
        PasswordValidationCallback pvc = new PasswordValidationCallback(clientSubject, "identityThree", "passwordTwo".toCharArray());
        CallerPrincipalCallback cpc = new CallerPrincipalCallback(clientSubject, (Principal) null);

        handle(callbackHandler, pvc, cpc);

        assertFalse("Password incorrectly verified", pvc.getResult());
    }

    /**
     * Test that an identity can be established skipping authentication in the CallbackHandler.
     */
    @Test
    public void testBypassAuthentication_Integrated() throws Exception {
        testBypassAuthentication(true, "identityOne", false);
    }

    /**
     * Test that an identity can be established skipping authentication in the CallbackHandler.
     *
     * Running NonIntegrated this is an ad-hoc identity, as the identity does not exist in the domain we must provide the role as well.
     */
    @Test
    public void testBypassAuthentication_NonIntegrated() throws Exception {
        testBypassAuthentication(false, "identityFour", true);
    }

    /**
     * Test that an identity can be established skipping authentication in the CallbackHandler, and override the assigned roles.
     */
    @Test
    public void testBypassAuthentication_RoleOverride_Integrated() throws Exception {
        testBypassAuthentication(true, "identityOne", true);
    }

    private void testBypassAuthentication(final boolean integrated, final String identity, final boolean overrideRole) throws Exception {
        Subject clientSubject = new Subject();
        JaspiAuthenticationContext jaspiAuthenticationContext = JaspiAuthenticationContext.newInstance(securityDomain, integrated);
        CallbackHandler callbackHandler = jaspiAuthenticationContext.createCallbackHandler();
        CallerPrincipalCallback cpc = new CallerPrincipalCallback(clientSubject, identity);

        if (overrideRole) {
            GroupPrincipalCallback gpc = new GroupPrincipalCallback(clientSubject, new String[] { "NewRole" });
            handle(callbackHandler, cpc, gpc);
        } else {
            handle(callbackHandler, cpc);
        }

        SecurityIdentity authorizedIdentity = jaspiAuthenticationContext.getAuthorizedIdentity();
        assertEquals("Unexpected Principal", identity, authorizedIdentity.getPrincipal().getName());
        assertTrue("Not in expected role", authorizedIdentity.getRoles().contains(overrideRole ? "NewRole" : "DefaultRole"));
        assertFalse("In unexpected role", authorizedIdentity.getRoles().contains(overrideRole ? "DefaultRole" : "NewRole"));
    }

    private void handle(CallbackHandler callbackHandler, Callback... callbacks) throws IOException, UnsupportedCallbackException {
       callbackHandler.handle(callbacks);
    }
}
