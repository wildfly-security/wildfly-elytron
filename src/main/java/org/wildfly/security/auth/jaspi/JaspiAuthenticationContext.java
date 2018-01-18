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

import static java.security.AccessController.doPrivileged;
import static org.wildfly.common.Assert.checkNotNullParam;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.callback.PasswordValidationCallback;

import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.manager.WildFlySecurityManager;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JaspiAuthenticationContext {

    private final ServerAuthenticationContext serverAuthenticationContext;
    private final String roleCategory = "servlet"; // TODO Make configurable and a list.
    private final Set<String> roles = new HashSet<>();

    JaspiAuthenticationContext(ServerAuthenticationContext serverAuthenticationContext) {
        this.serverAuthenticationContext = serverAuthenticationContext;
    }

    public static JaspiAuthenticationContext newInstance(final SecurityDomain securityDomain) {
        return new JaspiAuthenticationContext(checkNotNullParam("securityDomain", securityDomain).createNewAuthenticationContext());
    }

    public CallbackHandler createCallbackHandler() {
        /*
         * This AuthenticationContext could implement the CallbackHandler interface directly but if we instead place it on a
         * factory method we could still look in the future at a tighter relationship with the ServerAuthenticationContext.
         */

        return new CallbackHandler() {

            private boolean nameAssigned = false; // This may be a red flag we even need a small set of states here.

            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                handleOne(callbacks, 0);
            }

            private void handleOne(Callback[] callbacks, int index) throws IOException, UnsupportedCallbackException {
                if (callbacks.length == index) {
                    return;
                }

                final Callback callback = callbacks[index];
                if (callback instanceof PasswordValidationCallback) {
                    PasswordValidationCallback pvc = (PasswordValidationCallback) callback;
                    // TODO Do we need null check or let SAC handle?
                    serverAuthenticationContext.setAuthenticationName(pvc.getUsername());
                    final Evidence evidence = new PasswordGuessEvidence(pvc.getPassword());
                    boolean verified = serverAuthenticationContext.verifyEvidence(evidence);
                    pvc.setResult(verified);
                    // Don't destroy the Evidence as the array is 'owned' by the PasswordValidationCallback.

                    if (verified) {
                        nameAssigned = true;
                        Credential credential = new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, pvc.getPassword()));
                        serverAuthenticationContext.addPrivateCredential(credential);

                        final Subject subject = pvc.getSubject();
                        if (subject != null && !subject.isReadOnly()) {
                            addPrivateCredential(subject, credential);
                        }
                    }
                } else if (callback instanceof CallerPrincipalCallback) {
                    final CallerPrincipalCallback cpc = (CallerPrincipalCallback) callback;
                    Principal callerPrincipal = cpc.getPrincipal();
                    final String callerName = cpc.getName();

                    final boolean authorized;
                    if (nameAssigned) {
                        if (callerPrincipal != null) {
                            authorized =serverAuthenticationContext.authorize(callerPrincipal);
                        } else if (callerName != null) {
                            authorized =serverAuthenticationContext.authorize(callerName);
                        } else {
                            // There is an authenticated identity (apparently) - just authorize as that identity.
                            authorized =serverAuthenticationContext.authorize();
                        }
                    } else {
                        // Step 1 - Set the identity.
                        if (callerPrincipal != null) {
                            serverAuthenticationContext.setAuthenticationPrincipal(callerPrincipal);
                        } else if (callerName != null) {
                            serverAuthenticationContext.setAuthenticationName(callerName);
                        }

                        // Step 2 - Authorize as same identity.
                        if (callerPrincipal != null || callerName != null) {
                            authorized = serverAuthenticationContext.authorize();
                        } else {
                            authorized = serverAuthenticationContext.authorizeAnonymous();
                        }
                    }

                    if (authorized) {
                        if (callerPrincipal == null) {
                            callerPrincipal = serverAuthenticationContext.getAuthorizedIdentity().getPrincipal();
                        }
                        final Subject subject = cpc.getSubject();
                        if (subject != null && !subject.isReadOnly()) {
                            subject.getPrincipals().add(callerPrincipal);
                        }
                    }
                } else if (callback instanceof GroupPrincipalCallback) {
                    GroupPrincipalCallback gpc = (GroupPrincipalCallback) callback;
                    String[] groups = gpc.getGroups();
                    if (groups != null && groups.length > 0) {
                        roles.addAll(Arrays.asList(groups));
                    }

                    // TODO - Need to check if we do want to add these to the Subject somehow.
                } else {
                    CallbackUtil.unsupported(callback);
                    handleOne(callbacks, index + 1);
                }

                handleOne(callbacks, index + 1);
            }
        };
    }

    /**
     * Get the authorized identity result of this authentication.
     *
     * @return the authorized identity
     * @throws IllegalStateException if the authentication is incomplete
     */
    public SecurityIdentity getAuthorizedIdentity() throws IllegalStateException {
        // Could be another sign we need states here, but having two state machines transitioning could make it easy for this to
        // be dropped to adding at the end may be a good idea.
        SecurityIdentity securityIdentity = serverAuthenticationContext.getAuthorizedIdentity();
        if (roles.size() > 0) {
            Roles roles = Roles.fromSet(this.roles);
            RoleMapper roleMapper = RoleMapper.constant(roles);
            securityIdentity = securityIdentity.withRoleMapper(roleCategory, roleMapper);
        }
        return securityIdentity;
    }

    private void addPrivateCredential(final Subject subject, final Credential credential) {
        Set<Object> privateCredentials = WildFlySecurityManager.isChecking()
                ? doPrivileged((PrivilegedAction<Set<Object>>) subject::getPrivateCredentials)
                : subject.getPrivateCredentials();
        privateCredentials.add(credential);
    }


}
