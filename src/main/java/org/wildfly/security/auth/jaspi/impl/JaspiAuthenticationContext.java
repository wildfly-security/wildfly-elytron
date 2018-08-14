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

package org.wildfly.security.auth.jaspi.impl;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;

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
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.manager.WildFlySecurityManager;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JaspiAuthenticationContext {

    private final SecurityDomain securityDomain;
    private final boolean integrated;

    private final String roleCategory;

    private volatile SecurityIdentity securityIdentity = null;
    private final Set<String> roles = new HashSet<>();


    JaspiAuthenticationContext(SecurityDomain securityDomain, boolean integrated, final String roleCategory) {
        this.securityDomain = securityDomain;
        this.integrated = integrated;
        this.roleCategory = roleCategory;
    }

    // TODO AdHoc Identity Permissions

    /*
     * Having a few options makes it feel like we should use a Builder, however that would lead to one more object per request.
     *
     * For these per-request classes we probably could make them self building with an activation step at the end that allows
     * their use whilst at the same time prohibits further config changes.
     */

    public static JaspiAuthenticationContext newInstance(final SecurityDomain securityDomain, final String roleCategory, final boolean integrated) {
        return new JaspiAuthenticationContext(checkNotNullParam("securityDomain", securityDomain), integrated, roleCategory);
    }

    public CallbackHandler createCallbackHandler() {
        return createCommonCallbackHandler(integrated);
    }

    private CallbackHandler createCommonCallbackHandler(final boolean integrated) {
        return new CallbackHandler() {

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
                    log.trace("Handling PasswordValidationCallback");
                    PasswordValidationCallback pvc = (PasswordValidationCallback) callback;

                    final String username = pvc.getUsername();
                    final Evidence evidence = new PasswordGuessEvidence(pvc.getPassword());

                    try {
                        SecurityIdentity authenticated = securityDomain.authenticate(username, evidence);
                        pvc.setResult(true);
                        securityIdentity = authenticated;  // Take a PasswordValidationCallback as always starting authentication again.
                    } catch (SecurityException e) {
                        log.trace("Authentication failed", e);
                        pvc.setResult(false);
                    }
                } else if (callback instanceof CallerPrincipalCallback) {
                    log.trace("Handling CallerPrincipalCallback");
                    final CallerPrincipalCallback cpc = (CallerPrincipalCallback) callback;
                    Principal callerPrincipal = cpc.getPrincipal();
                    final String callerName = cpc.getName();
                    if (callerPrincipal == null && callerName != null) {
                        callerPrincipal = new NamePrincipal(callerName);
                    }
                    log.tracef("Caller Principal = %s", callerPrincipal);

                    SecurityIdentity authorizedIdentity = null;
                    if (callerPrincipal == null) {
                        // Special case for null caller Prinicpal
                        if (integrated && securityIdentity != null) {
                            authorizedIdentity = securityIdentity.createRunAsAnonymous();
                        } else if (integrated) {
                            ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
                            sac.authorizeAnonymous();
                            authorizedIdentity = sac.getAuthorizedIdentity();
                        } else {
                            authorizedIdentity = securityDomain.getAnonymousSecurityIdentity();
                        }
                    } else if (securityIdentity != null) {
                        boolean authorizationRequired = (integrated && !securityIdentity.getPrincipal().equals(callerPrincipal));
                        authorizedIdentity = securityIdentity.createRunAsIdentity(callerPrincipal, authorizationRequired); // If we are integrated we want an authorization check.
                    } else {
                        if (integrated) {
                            ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
                            sac.setAuthenticationPrincipal(callerPrincipal);
                            if (sac.authorize()) {
                                authorizedIdentity = sac.getAuthorizedIdentity();
                            }
                        } else {
                            authorizedIdentity = securityDomain.createAdHocIdentity(callerPrincipal);
                        }
                    }

                    if (authorizedIdentity != null) {
                        securityIdentity = authorizedIdentity;
                        final Subject subject = cpc.getSubject();
                        if (subject != null && !subject.isReadOnly()) {
                            subject.getPrincipals().add(authorizedIdentity.getPrincipal());
                        }
                    } else {
                        throw log.authorizationFailed();
                    }
                } else if (callback instanceof GroupPrincipalCallback) {
                    log.trace("Handling GroupPrincipalCallback");
                    log.trace("Handling GroupPrincipalCallback");
                    GroupPrincipalCallback gpc = (GroupPrincipalCallback) callback;
                    String[] groups = gpc.getGroups();
                    if (groups != null && groups.length > 0) {
                        roles.addAll(Arrays.asList(groups));
                    }
                    // TODO - Add anything to subject?
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
        SecurityIdentity securityIdentity = this.securityIdentity;
        if (roles.size() > 0) {
            log.trace("Assigning roles to resulting SecurityIdentity");
            Roles roles = Roles.fromSet(this.roles);
            RoleMapper roleMapper = RoleMapper.constant(roles);
            securityIdentity = securityIdentity.withRoleMapper(roleCategory, roleMapper);
        } else {
            log.trace("No roles request of CallbackHandler.");
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
