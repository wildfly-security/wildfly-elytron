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

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.wildfly.security.auth.principal.NamePrincipal;

/**
 * A {@link javax.security.auth.spi.LoginModule} implementation used in the JAAS security realm tests. It uses a static
 * map of username -> password to determine if a login is successful or not.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class TestLoginModule implements LoginModule {

    private final Map<String, char[]> usersMap = new HashMap<String, char[]>();
    private Principal principal;
    private Subject subject;
    private CallbackHandler handler;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.handler = callbackHandler;
        this.usersMap.put("elytron", "passwd12#$".toCharArray());
        this.usersMap.put("javajoe", "$#21pass".toCharArray());
        this.usersMap.put("javaduke", "dukepass!@34".toCharArray());
    }

    @Override
    public boolean login() throws LoginException {
        // obtain the incoming username and password from the callback handler
        NameCallback nameCallback = new NameCallback("Username");
        PasswordCallback passwordCallback = new PasswordCallback("Password", false);
        Callback[] callbacks = new Callback[]{nameCallback, passwordCallback};
        try {
            this.handler.handle(callbacks);
        } catch(UnsupportedCallbackException | IOException e) {
            throw new LoginException("Error handling callback: " + e.getMessage());
        }

        final String username = nameCallback.getName();
        this.principal = new NamePrincipal(username);
        final char[] password = passwordCallback.getPassword();

        char[] storedPassword = this.usersMap.get(username);
        return Arrays.equals(storedPassword, password);
    }

    @Override
    public boolean commit() throws LoginException {
        this.subject.getPrincipals().add(this.principal);
        // add a caller principal group for testing purposes.
        final Group group = new TestGroup("CallerPrincipal");
        group.addMember(new NamePrincipal("auth-caller"));
        this.subject.getPrincipals().add(group);
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        this.subject.getPrincipals().clear();
        return true;
    }

    /**
     * A {@code Group} implementation used in the tests to store the caller principal.
     */
    private class TestGroup implements Group {

        private String name;
        private HashSet<Principal> principals;

        public TestGroup(final String name) {
            this.name = name;
            this.principals = new HashSet<Principal>();
        }

        @Override
        public String getName() {
            return this.name;
        }

        @Override
        public boolean addMember(Principal user) {
            return this.principals.add(user);
        }

        @Override
        public boolean removeMember(Principal user) {
            return this.principals.remove(user);
        }

        @Override
        public boolean isMember(Principal member) {
            return this.principals.contains(member);
        }

        @Override
        public Enumeration<? extends Principal> members() {
            return Collections.enumeration(this.principals);
        }
    }
}
