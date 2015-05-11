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

package org.wildfly.security.auth.provider;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.spi.AuthenticatedRealmIdentity;
import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.auth.spi.RealmUnavailableException;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.manager.WildFlySecurityManager;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * A JAAS based {@link SecurityRealm} implementation.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JAASSecurityRealm implements SecurityRealm {

    private final String loginConfiguration;

    private CallbackHandler handler;

    public JAASSecurityRealm(final String loginConfiguration) {
        this(loginConfiguration, null);
    }

    public JAASSecurityRealm(final String loginConfiguration, final CallbackHandler handler) {
        this.loginConfiguration = loginConfiguration;
        this.handler = handler;
    }

    @Override
    public RealmIdentity createRealmIdentity(Principal principal) throws RealmUnavailableException {
        if (principal instanceof NamePrincipal == false) {
            throw ElytronMessages.log.invalidPrincipalType(NamePrincipal.class, principal == null ? null : principal.getClass());
        }
        return new JAASRealmIdentity(principal);
    }

    @Override
    public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
        if (handler == null) {
            // we will be using the default handler that only supports char[] and String credentials.
            if (char[].class.isAssignableFrom(credentialType) || String.class.isAssignableFrom(credentialType) || ClearPassword.class.isAssignableFrom(credentialType)) {
                return CredentialSupport.VERIFIABLE_ONLY;
            }
            else {
                return CredentialSupport.UNSUPPORTED;
            }
        }
        else {
            // if a custom handler is set then the credential type is possibly verifiable.
            return CredentialSupport.POSSIBLY_VERIFIABLE;
        }
    }

    private class JAASRealmIdentity implements RealmIdentity {

        private final Principal principal;

        private Subject subject;

        private JAASRealmIdentity(final Principal principal) {
            this.principal = principal;
        }

        @Override
        public Principal getPrincipal() throws RealmUnavailableException {
            return this.principal;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
            if (handler == null) {
                // we will be using the default handler that only supports char[] and String credentials.
                if (char[].class.isAssignableFrom(credentialType) || String.class.isAssignableFrom(credentialType) || ClearPassword.class.isAssignableFrom(credentialType)) {
                    return CredentialSupport.VERIFIABLE_ONLY;
                }
                else {
                    return CredentialSupport.UNSUPPORTED;
                }
            }
            else {
                // if a custom handler is set then the credential type is possibly verifiable.
                return CredentialSupport.POSSIBLY_VERIFIABLE;
            }
        }

        @Override
        public <C> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
            return null;
        }

        @Override
        public boolean verifyCredential(Object credential) throws RealmUnavailableException {
            boolean successfulLogin;
            final CallbackHandler callbackHandler = this.createCallbackHandler(credential);
            final Subject subject = new Subject();
            final LoginContext context  = createLoginContext(loginConfiguration, subject, callbackHandler);

            try {
                context.login();
                successfulLogin = true;
                this.subject = subject;
            } catch (LoginException le) {
                ElytronMessages.log.debugJAASAuthenticationFailure(principal, le);
                successfulLogin = false;
            }
            return successfulLogin;
        }

        @Override
        public AuthenticatedRealmIdentity getAuthenticatedRealmIdentity() throws RealmUnavailableException {
            return new JAASAuthenticatedRealmIdentity(this.principal, this.subject);
        }

        private LoginContext createLoginContext(final String loginConfig, final Subject subject, final CallbackHandler handler) throws RealmUnavailableException {
            if (WildFlySecurityManager.isChecking()) {
                try {
                    return AccessController.doPrivileged(new CreateLoginContextAction(loginConfig, subject, handler));
                } catch (PrivilegedActionException pae) {
                    throw ElytronMessages.log.failedToCreateLoginContext(pae.getCause());
                }
            }
            else {
                try {
                    return new LoginContext(loginConfig, subject, handler);
                } catch (LoginException le) {
                    throw ElytronMessages.log.failedToCreateLoginContext(le);
                }
            }
        }

        private CallbackHandler createCallbackHandler(final Object credential) throws RealmUnavailableException {
            if (handler == null) {
                return new DefaultCallbackHandler(this.principal, credential);
            }
            else {
                try {
                    final CallbackHandler callbackHandler = handler.getClass().newInstance();
                    // preserve backwards compatibility: custom handlers were allowed in the past as long as they had a public setSecurityInfo method.
                    final Method setSecurityInfo = handler.getClass().getMethod("setSecurityInfo", Principal.class, Object.class);
                    setSecurityInfo.invoke(callbackHandler, this.principal, credential);
                    return callbackHandler;
                } catch (Exception e) {
                    throw ElytronMessages.log.failedToInstantiateCustomHandler(e);
                }
            }
        }
    }

    private class DefaultCallbackHandler implements CallbackHandler {

        private final Principal principal;
        private final Object credential;

        private DefaultCallbackHandler(final Principal principal, final Object credential) {
            this.principal = principal;
            this.credential = credential;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            if (callbacks == null)
                throw ElytronMessages.log.invalidNullCallbackArray();

            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    NameCallback nameCallback = (NameCallback) callback;
                    if (principal != null)
                        nameCallback.setName(this.principal.getName());
                }
                else if (callback instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback) callback;
                    if (this.credential instanceof char[]) {
                        passwordCallback.setPassword((char[]) credential);
                    }
                    else if (this.credential instanceof String) {
                        passwordCallback.setPassword(((String) credential).toCharArray());
                    }
                    else if (this.credential instanceof ClearPassword) {
                        passwordCallback.setPassword(((ClearPassword) credential).getPassword());
                    }
                    else {
                        throw ElytronMessages.log.failedToConvertCredentialToPassword(callback);
                    }
                }
                else {
                    CallbackUtil.unsupported(callback);
                }
            }
        }
    }

    private class JAASAuthenticatedRealmIdentity implements AuthenticatedRealmIdentity {

        private final Principal principal;
        private final Subject subject;

        private JAASAuthenticatedRealmIdentity(final Principal principal, final Subject subject) {
            this.principal = principal;
            this.subject = subject;
            // todo investigate subject for a caller principal for backwards compatibility.
        }

        @Override
        public void dispose() {
            // todo call JAAS logout here if subject is not null?
        }

        @Override
        public Principal getPrincipal() {
            return principal;
        }
    }

    private class CreateLoginContextAction implements PrivilegedExceptionAction<LoginContext> {

        private final String loginConfig;
        private final Subject subject;
        private final CallbackHandler handler;

        private CreateLoginContextAction(final String loginConfig, final Subject subject, final CallbackHandler handler) {
            this.loginConfig = loginConfig;
            this.subject = subject;
            this.handler = handler;
        }

        @Override
        public LoginContext run() throws Exception {
            return new LoginContext(this.loginConfig, this.subject, this.handler);
        }
    }
}
