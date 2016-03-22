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

package org.wildfly.security.auth.realm;

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
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.Set;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.manager.WildFlySecurityManager;

/**
 * A JAAS based {@link SecurityRealm} implementation.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JaasSecurityRealm implements SecurityRealm {

    private final String loginConfiguration;

    private final CallbackHandler handler;

    /**
     * Construct a new instance.
     *
     * @param loginConfiguration the login configuration name to use
     */
    public JaasSecurityRealm(final String loginConfiguration) {
        this(loginConfiguration, null);
    }

    /**
     * Construct a new instance.
     *
     * @param loginConfiguration the login configuration name to use
     * @param handler the JAAS callback handler to use
     */
    public JaasSecurityRealm(final String loginConfiguration, final CallbackHandler handler) {
        this.loginConfiguration = loginConfiguration;
        this.handler = handler;
    }

    @Override
    public RealmIdentity getRealmIdentity(final String name, final Principal principal, final Evidence evidence) throws RealmUnavailableException {
        if (name == null) {
            return RealmIdentity.NON_EXISTENT;
        }
        return new JaasRealmIdentity(new NamePrincipal(name));
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidenceType", evidenceType);
        return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    private LoginContext createLoginContext(final String loginConfig, final Subject subject, final CallbackHandler handler) throws RealmUnavailableException {
        if (WildFlySecurityManager.isChecking()) {
            try {
                return AccessController.doPrivileged((PrivilegedExceptionAction<LoginContext>) () -> new LoginContext(loginConfig, subject, handler));
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

    private CallbackHandler createCallbackHandler(final Principal principal, final PasswordGuessEvidence evidence) throws RealmUnavailableException {
        if (handler == null) {
            return new DefaultCallbackHandler(principal, evidence);
        }
        else {
            try {
                final CallbackHandler callbackHandler = handler.getClass().newInstance();
                // preserve backwards compatibility: custom handlers were allowed in the past as long as they had a public setSecurityInfo method.
                final Method setSecurityInfo = handler.getClass().getMethod("setSecurityInfo", Principal.class, Object.class);
                setSecurityInfo.invoke(callbackHandler, principal, evidence);
                return callbackHandler;
            } catch (Exception e) {
                throw ElytronMessages.log.failedToInstantiateCustomHandler(e);
            }
        }
    }

    private class JaasRealmIdentity implements RealmIdentity {

        private final Principal principal;

        private Subject subject;

        private JaasRealmIdentity(final Principal principal) {
            this.principal = principal;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            return JaasSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return getCredential(credentialType, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return null;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            return JaasSecurityRealm.this.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            if (evidence instanceof PasswordGuessEvidence) {
                this.subject = null;
                boolean successfulLogin;
                final CallbackHandler callbackHandler = createCallbackHandler(principal, (PasswordGuessEvidence) evidence);
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
            } else {
                return false;
            }
        }

        public boolean exists() throws RealmUnavailableException {
            /* we don't really know that the identity exists, but we know that there is always
             * an authorization identity so that's as good as {@code true}
             */
            return true;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            return new JaasAuthorizationIdentity(this.principal, this.subject);
        }

        public boolean createdBySecurityRealm(final SecurityRealm securityRealm) {
            return JaasSecurityRealm.this == securityRealm;
        }
    }

    private class DefaultCallbackHandler implements CallbackHandler {

        private final Principal principal;
        private final PasswordGuessEvidence evidence;

        private DefaultCallbackHandler(final Principal principal, final PasswordGuessEvidence evidence) {
            this.principal = principal;
            this.evidence = evidence;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            Assert.checkNotNullParam("callbacks", callbacks);

            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    NameCallback nameCallback = (NameCallback) callback;
                    if (principal != null)
                        nameCallback.setName(this.principal.getName());
                }
                else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(evidence.getGuess());
                }
                else {
                    CallbackUtil.unsupported(callback);
                }
            }
        }
    }

    private class JaasAuthorizationIdentity implements AuthorizationIdentity {

        private static final String CALLER_PRINCIPAL_GROUP = "CallerPrincipal";

        private final Principal principal;
        private Principal callerPrincipal;
        private final Subject subject;

        private JaasAuthorizationIdentity(final Principal principal, final Subject subject) {
            this.principal = principal;
            this.subject = subject;
            // check if the subject has a caller principal group - if it has then we should use that principal.
            this.callerPrincipal = getCallerPrincipal(subject);
        }

        /**
         * Obtains the caller principal from the specified {@link Subject}. This method looks for a group called {@code
         * CallerPrincipal} and if it finds one it returns the first {@link java.security.Principal} in the group.
         *
         * @param subject the {@link javax.security.auth.Subject} to be inspected.
         * @return the first {@link java.security.Principal} found in the {@code CallerPrincipal} group or {@code null} if
         * a caller principal couldn't be found.
         */
        private Principal getCallerPrincipal(Subject subject) {
            Principal callerPrincipal = null;
            if (subject != null) {
                Set<Principal> principals = subject.getPrincipals();
                if (principals != null && !principals.isEmpty()) {
                    for (Principal principal : principals) {
                        if (principal instanceof Group && principal.getName().equals(CALLER_PRINCIPAL_GROUP)) {
                            Enumeration<? extends Principal> enumeration = ((Group) principal).members();
                            if (enumeration.hasMoreElements()) {
                                callerPrincipal = enumeration.nextElement();
                                break;
                            }
                        }
                    }
                }
            }
            return callerPrincipal;
        }
    }
}
