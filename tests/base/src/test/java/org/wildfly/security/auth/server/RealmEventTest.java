/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wildfly.security.auth.server;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.callback.RequestInformationCallback;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import static org.junit.Assert.fail;
import static org.wildfly.security.authz.RoleDecoder.KEY_SOURCE_ADDRESS;

public class RealmEventTest {

    private static SecurityDomain usersDomain;
    private static CustomRealm usersRealm;
    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    private ServerAuthenticationContext setupAndGetServerAuthenticationContext() throws IOException, UnsupportedCallbackException, URISyntaxException {
        Security.addProvider(provider);

        usersRealm = new CustomRealm();
        SecurityDomain.Builder builder = SecurityDomain.builder();
        builder.addRealm("users", usersRealm).build();
        builder.setDefaultRealmName("users");
        builder.setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.from(new LoginPermission()));
        usersDomain = builder.build();

        ServerAuthenticationContext serverAuthenticationContext = usersDomain.createNewAuthenticationContext();
        serverAuthenticationContext.addRuntimeAttributes(createRuntimeAttributesWithSourceAddress());

        HashMap<String, Object> props = new HashMap<>();
        props.put("Request-URI", new URI("www.test-request-uri.org"));
        CallbackHandler callbackHandler = serverAuthenticationContext.createCallbackHandler();
        callbackHandler.handle(new Callback[]{new RequestInformationCallback(props)});
        return serverAuthenticationContext;
    }

    @Test
    public void testRealmSuccessfulAuthenticationEvent() throws IOException, UnsupportedCallbackException, URISyntaxException {
        ServerAuthenticationContext serverAuthenticationContext = setupAndGetServerAuthenticationContext();
        try {
            serverAuthenticationContext.setAuthenticationName("myadmin");
            serverAuthenticationContext.addPublicCredential(new PasswordCredential(
                    PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                            new ClearPasswordSpec("mypassword".toCharArray()))));

            serverAuthenticationContext.authorize();
        } catch (RealmUnavailableException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            fail();
        }
        serverAuthenticationContext.succeed();
        if (usersRealm.wasAssertionError) {
            Assert.fail("Realm successful authentication event did not contain expected information");
        }
    }

    @Test
    public void testRealmFailedAuthenticationEvent() throws NoSuchAlgorithmException, IOException, UnsupportedCallbackException, InvalidKeySpecException, URISyntaxException {
        ServerAuthenticationContext serverAuthenticationContext = setupAndGetServerAuthenticationContext();
        serverAuthenticationContext.setAuthenticationName("myadmin");
        serverAuthenticationContext.addPublicCredential(new PasswordCredential(
                PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                        new ClearPasswordSpec("wrongPassword".toCharArray()))));
        serverAuthenticationContext.fail();
        if (usersRealm.wasAssertionError) {
            Assert.fail("Realm failed authentication event did not contain expected information");
        }
    }

    private Attributes createRuntimeAttributesWithSourceAddress() {
        MapAttributes runtimeAttributes = new MapAttributes();
        runtimeAttributes.addFirst(KEY_SOURCE_ADDRESS, "10.12.14.16");
        return runtimeAttributes;
    }
}
