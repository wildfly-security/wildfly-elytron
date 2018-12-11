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

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.jaspi._private.ElytronMessages.log;
import static org.wildfly.security.auth.jaspi.impl.SecurityActions.doPrivileged;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
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
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.permission.ElytronPermission;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class JaspiAuthenticationContext {

    static final ElytronPermission CREATE_AUTH_CONTEXT = ElytronPermission.forName("createServerAuthenticationContext");

    private final SecurityDomain securityDomain;
    private final boolean integrated;

    private volatile SecurityIdentity securityIdentity = null;
    private final Set<String> roles = new HashSet<>();


    JaspiAuthenticationContext(SecurityDomain securityDomain, boolean integrated) {
        this.securityDomain = securityDomain;
        this.integrated = integrated;
    }

    /*
     * Having a few options makes it feel like we should use a Builder, however that would lead to one more object per request.
     *
     * For these per-request classes we probably could make them self building with an activation step at the end that allows
     * their use whilst at the same time prohibits further config changes.
     */

    // TODO Can we find a way to create this from the SecurityDomain similar to ServerAuthContext?

    public static JaspiAuthenticationContext newInstance(final SecurityDomain securityDomain, final boolean integrated) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CREATE_AUTH_CONTEXT);
        }
        return new JaspiAuthenticationContext(checkNotNullParam("securityDomain", securityDomain), integrated);
    }

    public CallbackHandler createCallbackHandler() {
        return createCommonCallbackHandler(integrated);
    }

    private CallbackHandler createCommonCallbackHandler(final boolean integrated) {
        return new CallbackHandler() {

            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                try {
                    doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                        handleOne(callbacks, 0);
                        return null;
                    });
                } catch (Exception e) {
                    if (e instanceof PrivilegedActionException) {
                        if (e.getCause() instanceof UnsupportedCallbackException) {
                            throw (UnsupportedCallbackException) e.getCause();
                        } else if (e.getCause() instanceof IOException) {
                            throw (IOException) e.getCause();
                        }
                    }
                    throw new IOException(e);
                }
            }

            private void handleOne(Callback[] callbacks, int index) throws IOException, UnsupportedCallbackException {
                if (callbacks.length == index) {
                    return;
                }

                final Callback callback = callbacks[index];
                if (callback instanceof PasswordValidationCallback) {
                    PasswordValidationCallback pvc = (PasswordValidationCallback) callback;

                    final String username = pvc.getUsername();
                    log.tracef("Handling PasswordValidationCallback for '%s'", username);
                    final Evidence evidence = new PasswordGuessEvidence(pvc.getPassword());

                    try {
                        // Not adding TRACE logging here as the transitions from SecurityDomain are logged.
                        SecurityIdentity authenticated = securityDomain.authenticate(username, evidence);
                        pvc.setResult(true);
                        securityIdentity = authenticated;  // Take a PasswordValidationCallback as always starting authentication again.
                    } catch (Exception e) {
                        log.trace("Authentication failed", e);
                        pvc.setResult(false);
                    }
                } else if (callback instanceof CallerPrincipalCallback) {
                    log.trace("Handling CallerPrincipalCallback");
                    final CallerPrincipalCallback cpc = (CallerPrincipalCallback) callback;
                    Principal originalPrincipal = cpc.getPrincipal();
                    final String callerName = cpc.getName();
                    final Principal callerPrincipal = originalPrincipal != null ? originalPrincipal : callerName != null ? new NamePrincipal(callerName) : null;

                    log.tracef("Original Principal = '%s', Caller Name = '%s', Resulting Principal = '%s'", originalPrincipal, callerName, callerPrincipal);

                    SecurityIdentity authorizedIdentity = null;
                    if (securityIdentity != null) {
                        if (callerPrincipal != null) {
                            boolean authorizationRequired = (integrated && !securityIdentity.getPrincipal().equals(callerPrincipal));
                         // If we are integrated we want an authorization check.
                            authorizedIdentity =  securityIdentity.createRunAsIdentity(callerPrincipal, authorizationRequired);
                        } else if (integrated) {
                            // Authorize as the authenticated identity.
                            ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
                            sac.importIdentity(securityIdentity);
                            sac.authorize();
                            authorizedIdentity = sac.getAuthorizedIdentity();
                        } else {
                            authorizedIdentity = securityIdentity;
                        }
                    } else {
                        if (callerPrincipal == null) {
                            // Do nothing and don't fail.
                            handleOne(callbacks, index + 1);
                            return;
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
        if (securityIdentity != null && roles.size() > 0) {
            if (log.isTraceEnabled()) {
                Iterator<String> rolesIterator = roles.iterator();
                StringBuilder sb = new StringBuilder(rolesIterator.next());
                while (rolesIterator.hasNext()) {
                    sb.append(",").append(rolesIterator.next());
                }
                log.tracef("Assigning roles '%s' to resulting SecurityIdentity", sb.toString());
            }
            Roles roles = Roles.fromSet(this.roles);
            RoleMapper roleMapper = RoleMapper.constant(roles);
            SecurityIdentity temp = securityIdentity;
            securityIdentity = doPrivileged((PrivilegedAction<SecurityIdentity>) (() -> temp.withDefaultRoleMapper(roleMapper)));
        } else {
            log.trace("No roles request of CallbackHandler.");
        }
        return securityIdentity;
    }

}
