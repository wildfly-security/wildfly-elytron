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

package org.wildfly.security.auth.server;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.wildfly.common.Assert;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.AnonymousAuthorizationCallback;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.PeerPrincipalCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.callback.ServerCredentialCallback;
import org.wildfly.security.auth.callback.SocketAddressCallback;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.permission.RunAsPrincipalPermission;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.event.RealmFailedAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmIdentityFailedAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmIdentitySuccessfulAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmSuccessfulAuthenticationEvent;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.SecurityIdentityEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Server-side authentication context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class ServerAuthenticationContext {

    private final SecurityDomain domain;
    private final AtomicReference<State> stateRef = new AtomicReference<>(INITIAL);
    private final MechanismConfiguration mechanismConfiguration;

    ServerAuthenticationContext(final SecurityDomain domain, final MechanismConfiguration mechanismConfiguration) {
        this.domain = domain;
        this.mechanismConfiguration = mechanismConfiguration;
    }

    /**
     * Get the authorized identity result of this authentication.
     *
     * @return the authorized identity
     * @throws IllegalStateException if the authentication is incomplete
     */
    public SecurityIdentity getAuthorizedIdentity() throws IllegalStateException {
        return stateRef.get().getAuthorizedIdentity();
    }

    /**
     * Set the authentication to anonymous, completing the authentication process.
     *
     * @throws IllegalStateException if the authentication is already complete
     */
    public void anonymous() throws IllegalStateException {
        State oldState;
        oldState = stateRef.get();
        if (oldState.getId() > REALM_ID) {
            throw ElytronMessages.log.alreadyComplete();
        }
        final CompleteState completeState = new CompleteState(domain.getAnonymousSecurityIdentity());
        while (! stateRef.compareAndSet(oldState, completeState)) {
            oldState = stateRef.get();
            if (oldState.getId() > REALM_ID) {
                throw ElytronMessages.log.alreadyComplete();
            }
        }
    }

    /**
     * Set the authentication name for this authentication.  If the name is already set, then the new name must be
     * equal to the old name, or else an exception is thrown.
     *
     * @param name the authentication name
     * @throws IllegalArgumentException if the name is syntactically invalid
     * @throws RealmUnavailableException if the realm is not available
     * @throws IllegalStateException if the authentication name was already set and there is a mismatch
     */
    public void setAuthenticationName(String name) throws IllegalArgumentException, RealmUnavailableException, IllegalStateException {
        Assert.checkNotNullParam("name", name);
        final AtomicReference<State> stateRef = this.stateRef;
        State oldState = stateRef.get();
        // early detection
        if (oldState.isDone()) {
            throw ElytronMessages.log.alreadyComplete();
        }
        final SecurityDomain domain = this.domain;
        final MechanismConfiguration mechanismConfiguration = this.mechanismConfiguration;
        final MechanismRealmConfiguration mechanismRealmConfiguration;
        if (oldState.getId() != INITIAL_ID) {
            mechanismRealmConfiguration = oldState.getMechanismRealmConfiguration();
        } else {
            final Collection<String> mechanismRealmNames = mechanismConfiguration.getMechanismRealmNames();
            final Iterator<String> iterator = mechanismRealmNames.iterator();
            if (iterator.hasNext()) {
                // use the default realm
                mechanismRealmConfiguration = mechanismConfiguration.getMechanismRealmConfiguration(iterator.next());
            } else {
                mechanismRealmConfiguration = MechanismRealmConfiguration.NO_REALM;
            }
        }
        name = rewriteAll(name, mechanismRealmConfiguration.getPreRealmRewriter(), mechanismConfiguration.getPreRealmRewriter(), domain.getPreRealmRewriter());
        // principal *must* be captured at this point
        final NamePrincipal principal = new NamePrincipal(name);
        name = rewriteAll(name, mechanismRealmConfiguration.getPostRealmRewriter(), mechanismConfiguration.getPostRealmRewriter(), domain.getPostRealmRewriter());
        String realmName = mapAll(name, mechanismRealmConfiguration.getRealmMapper(), mechanismConfiguration.getRealmMapper(), domain.getRealmMapper(), domain.getDefaultRealmName());
        final RealmInfo realmInfo = domain.getRealmInfo(realmName);
        name = rewriteAll(name, mechanismRealmConfiguration.getFinalRewriter(), mechanismConfiguration.getFinalRewriter(), realmInfo.getNameRewriter());
        // name should remain
        if (oldState.getId() == ASSIGNED_ID) {
            if (! oldState.getAuthenticationPrincipal().getName().equals(name) || oldState.getMechanismRealmConfiguration() != mechanismRealmConfiguration) {
                throw log.nameAlreadySet();
            }
            // no further action needed
            return;
        }
        final SecurityRealm securityRealm = realmInfo.getSecurityRealm();
        final RealmIdentity realmIdentity = securityRealm.getRealmIdentity(name, null, null);
        boolean ok = false;
        try {
            NameAssignedState newState = new NameAssignedState(domain, principal, realmInfo, realmIdentity, mechanismRealmConfiguration);
            while (! stateRef.compareAndSet(oldState, newState)) {
                oldState = stateRef.get();
                if (oldState.isDone()) {
                    throw ElytronMessages.log.alreadyComplete();
                } else if (oldState.getId() == ASSIGNED_ID) {
                    if (! oldState.getAuthenticationPrincipal().equals(principal)) {
                        throw log.nameAlreadySet();
                    }
                    // no further action needed
                    return;
                }
            }
            ok = true;
        } finally {
            if (! ok) realmIdentity.dispose();
        }
    }

    /**
     * Set the authentication principal for this authentication.  Calling this method initiates authentication.
     *
     * @param principal the authentication principal
     * @throws IllegalArgumentException if the principal cannot be mapped to a name, or the mapped name is syntactically invalid
     * @throws RealmUnavailableException if the realm is not available
     * @throws IllegalStateException if the authentication name was already set
     */
    public void setAuthenticationPrincipal(Principal principal) throws IllegalArgumentException, RealmUnavailableException, IllegalStateException {
        Assert.checkNotNullParam("principal", principal);
        String name = domain.getPrincipalDecoder().getName(principal);
        if (name == null) {
            throw ElytronMessages.log.unrecognizedPrincipalType(principal);
        }
        setAuthenticationName(name);
    }

    /**
     * Determine if the given name refers to the same identity as the currently set authentication name.
     *
     * @param name the authentication name
     * @return {@code true} if the name matches the current identity, {@code false} otherwise
     * @throws IllegalArgumentException if the name is syntactically invalid
     * @throws RealmUnavailableException if the realm is not available
     * @throws IllegalStateException if the authentication name was already set
     */
    public boolean isSameName(String name) throws IllegalArgumentException, RealmUnavailableException, IllegalStateException {
        Assert.checkNotNullParam("name", name);
        final SecurityDomain domain = this.domain;
        final MechanismConfiguration mechanismConfiguration = this.mechanismConfiguration;
        final MechanismRealmConfiguration mechanismRealmConfiguration;
        final State state = stateRef.get();
        if (state.getId() != INITIAL_ID) {
            mechanismRealmConfiguration = state.getMechanismRealmConfiguration();
        } else {
            final Collection<String> mechanismRealmNames = mechanismConfiguration.getMechanismRealmNames();
            final Iterator<String> iterator = mechanismRealmNames.iterator();
            if (iterator.hasNext()) {
                // use the default realm
                mechanismRealmConfiguration = mechanismConfiguration.getMechanismRealmConfiguration(iterator.next());
            } else {
                mechanismRealmConfiguration = MechanismRealmConfiguration.NO_REALM;
            }
        }
        name = rewriteAll(name, mechanismRealmConfiguration.getPreRealmRewriter(), mechanismConfiguration.getPreRealmRewriter(), domain.getPreRealmRewriter());
        String realmName = mapAll(name, mechanismRealmConfiguration.getRealmMapper(), mechanismConfiguration.getRealmMapper(), domain.getRealmMapper(), domain.getDefaultRealmName());
        RealmInfo realmInfo = domain.getRealmInfo(realmName);
        name = rewriteAll(name, mechanismRealmConfiguration.getPostRealmRewriter(), mechanismConfiguration.getPostRealmRewriter(), domain.getPostRealmRewriter());
        name = rewriteAll(name, mechanismRealmConfiguration.getFinalRewriter(), mechanismConfiguration.getFinalRewriter(), realmInfo.getNameRewriter());
        return state.getAuthenticationPrincipal().equals(new NamePrincipal(name));
    }

    /**
     * Determine if the current authentication identity actually exists in the realm.
     *
     * @return {@code true} if the identity exists, {@code false} otherwise
     * @throws RealmUnavailableException if the realm failed to access the identity
     * @throws IllegalStateException if the authentication name was already set
     */
    public boolean exists() throws RealmUnavailableException, IllegalStateException {
        return stateRef.get().getRealmIdentity().exists();
    }

    /**
     * Determine if the given principal refers to the same identity as the currently set authentication name.
     *
     * @param principal the authentication name
     * @return {@code true} if the name matches the current identity, {@code false} otherwise
     * @throws IllegalArgumentException if the name is syntactically invalid
     * @throws RealmUnavailableException if the realm is not available
     * @throws IllegalStateException if the authentication name was already set
     */
    public boolean isSamePrincipal(Principal principal) throws IllegalArgumentException, RealmUnavailableException, IllegalStateException {
        Assert.checkNotNullParam("principal", principal);
        String name = domain.getPrincipalDecoder().getName(principal);
        return name != null && isSameName(name);
    }

    /**
     * Mark this authentication as "failed".  The context cannot be used after this method is called.
     *
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public void fail() throws IllegalStateException {
        State oldState;
        do {
            oldState = stateRef.get();
            if (oldState.isDone()) {
                throw ElytronMessages.log.alreadyComplete();
            }
            if (! oldState.isStarted()) {
                throw ElytronMessages.log.noAuthenticationInProgress();
            }
        } while (!stateRef.compareAndSet(oldState, FAILED));
        final RealmIdentity realmIdentity = oldState.getRealmIdentity();
        final SecurityRealm securityRealm = oldState.getRealmInfo().getSecurityRealm();
        SecurityRealm.safeHandleRealmEvent(securityRealm, new RealmFailedAuthenticationEvent(realmIdentity, null, null));
        if (oldState.getId() == ASSIGNED_ID) {
            realmIdentity.dispose();
        }
    }

    /**
     * Attempt to authorize an authentication attempt.  If the authorization is successful, {@code true} is returned and
     * the context is placed in the "authorized" state with the new authorization identity.  If the authorization fails,
     * {@code false} is returned and the state of the context is unchanged.
     *
     * @return {@code true} if the authorization succeeded, {@code false} otherwise
     * @throws RealmUnavailableException if the realm is not available
     * @throws IllegalStateException if the authentication name was not set or authentication was already complete
     */
    public boolean authorize() throws RealmUnavailableException, IllegalStateException {
        State oldState = stateRef.get();
        if (oldState.isDone()) {
            throw ElytronMessages.log.alreadyComplete();
        }
        if (oldState.getId() == AUTHORIZED_ID) {
            return true;
        }
        if (oldState.getId() < ASSIGNED_ID) {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        final RealmIdentity realmIdentity = oldState.getRealmIdentity();
        if (! realmIdentity.exists()) {
            return false;
        }

        final RealmInfo realmInfo = oldState.getRealmInfo();
        final Principal authenticationPrincipal = oldState.getAuthenticationPrincipal();

        final AuthorizationIdentity authorizationIdentity = realmIdentity.getAuthorizationIdentity();

        final SecurityIdentity securityIdentity = domain.transform(new SecurityIdentity(domain, authenticationPrincipal, realmInfo, authorizationIdentity, domain.getCategoryRoleMappers()));
        if (securityIdentity.implies(new LoginPermission())) {
            final AuthorizedState authorizedState = new AuthorizedState(securityIdentity, authenticationPrincipal, realmInfo, realmIdentity, oldState.getMechanismRealmConfiguration());
            while (! stateRef.compareAndSet(oldState, authorizedState)) {
                oldState = stateRef.get();
                if (oldState.isDone()) {
                    throw ElytronMessages.log.alreadyComplete();
                }
                if (oldState.getId() == AUTHORIZED_ID) {
                    // one way or another, we were already authorized
                    return true;
                }
                if (oldState.getId() < ASSIGNED_ID) {
                    throw ElytronMessages.log.noAuthenticationInProgress();
                }
                assert oldState.getId() == ASSIGNED_ID;
                // it is impossible for the assigned state to change its identity
                assert oldState.getRealmIdentity() == realmIdentity;
            }
            SecurityRealm.safeHandleRealmEvent(realmInfo.getSecurityRealm(), new RealmIdentitySuccessfulAuthorizationEvent(securityIdentity.getAuthorizationIdentity(), securityIdentity.getPrincipal(), authenticationPrincipal));
            oldState.getRealmIdentity().dispose();
            return true;
        } else {
            SecurityRealm.safeHandleRealmEvent(realmInfo.getSecurityRealm(), new RealmIdentityFailedAuthorizationEvent(securityIdentity.getAuthorizationIdentity(), securityIdentity.getPrincipal(), authenticationPrincipal));
            return false;
        }
    }

    /**
     * Attempt to authorize a change to a new user.  If the authorization is successful, {@code true} is returned and
     * the context is placed in the "authorized" state with the new authorization identity.  If the authorization fails,
     * {@code false} is returned and the state of the context is unchanged.
     *
     * @param name the authorization name
     * @return {@code true} if the authorization succeeded, {@code false} otherwise
     * @throws IllegalArgumentException if the name is syntactically invalid
     * @throws RealmUnavailableException if the realm is not available
     * @throws IllegalStateException if the authentication name was not set or authentication was already complete
     */
    public boolean authorize(String name) throws IllegalArgumentException, RealmUnavailableException, IllegalStateException {
        Assert.checkNotNullParam("name", name);

        // we need an initial authorization to proceed
        if (! authorize()) {
            return false;
        }

        // now get & recheck state
        State oldState;
        AuthorizedState newState;
        for (;;) {
            oldState = stateRef.get();
            if (oldState.isDone()) {
                throw ElytronMessages.log.alreadyComplete();
            }
            if (! oldState.isStarted()) {
                throw ElytronMessages.log.noAuthenticationInProgress();
            }
            // having passed authorization above, it is impossible to be in any other state than authorized at this point
            assert oldState.getId() == AUTHORIZED_ID;

            final SecurityDomain domain = this.domain;
            final MechanismConfiguration mechanismConfiguration = this.mechanismConfiguration;
            final MechanismRealmConfiguration mechanismRealmConfiguration = oldState.getMechanismRealmConfiguration();

            // rewrite the proposed name
            name = rewriteAll(name, mechanismRealmConfiguration.getPreRealmRewriter(), mechanismConfiguration.getPreRealmRewriter(), domain.getPreRealmRewriter());
            // pause here and see if we're really authorizing a new identity
            // principal *must* be captured at this point
            final NamePrincipal principal = new NamePrincipal(name);
            if (oldState.getAuthenticationPrincipal().equals(principal)) {
                // it's the same identity; just succeed as we are already authorized per above
                succeed();
                return true;
            }

            // check the run-as permission on the old identity
            if (! oldState.getAuthorizedIdentity().implies(new RunAsPrincipalPermission(principal.getName()))) {
                return false;
            }

            // continue rewriting to locate the new authorization identity
            name = rewriteAll(name, mechanismRealmConfiguration.getPostRealmRewriter(), mechanismConfiguration.getPostRealmRewriter(), domain.getPostRealmRewriter());
            String realmName = mapAll(name, mechanismRealmConfiguration.getRealmMapper(), mechanismConfiguration.getRealmMapper(), domain.getRealmMapper(), domain.getDefaultRealmName());
            final RealmInfo realmInfo = domain.getRealmInfo(realmName);
            name = rewriteAll(name, mechanismRealmConfiguration.getFinalRewriter(), mechanismConfiguration.getFinalRewriter(), realmInfo.getNameRewriter());

            // now construct the new identity
            final SecurityRealm securityRealm = realmInfo.getSecurityRealm();
            final RealmIdentity realmIdentity = securityRealm.getRealmIdentity(name, null, null);
            boolean ok = false;
            try {
                if (! realmIdentity.exists()) {
                    return false;
                }
                final AuthorizationIdentity authorizationIdentity = realmIdentity.getAuthorizationIdentity();
                final SecurityIdentity newIdentity = domain.transform(new SecurityIdentity(domain, principal, realmInfo, authorizationIdentity, domain.getCategoryRoleMappers()));

                // make sure the new identity is authorized
                if (! newIdentity.implies(new LoginPermission())) {
                    return false;
                }

                // create and switch to new authorized state
                newState = new ServerAuthenticationContext.AuthorizedState(newIdentity, principal, realmInfo, realmIdentity, mechanismRealmConfiguration);

                // if we do not succeed, try it again...
                if (stateRef.compareAndSet(oldState, newState)) {
                    // clean up old state, keep new state
                    ok = true;
                    // do this second in the unlikely event that it fails
                    oldState.getRealmIdentity().dispose();
                    return true;
                }
            } finally {
                if (! ok) {
                    realmIdentity.dispose();
                }
            }
        }
    }

    /**
     * Mark this authentication as "successful".  The context cannot be used after this method is called, however
     * the authorized identity may thereafter be accessed via the {@link #getAuthorizedIdentity()} method.  If no
     * authentication actually happened, then authentication will complete anonymously.
     *
     * @throws IllegalStateException if authentication is already completed
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    public void succeed() throws IllegalStateException, RealmUnavailableException {
        State oldState = stateRef.get();
        if (oldState.isDone()) {
            throw ElytronMessages.log.alreadyComplete();
        }
        if (! oldState.isStarted()) {
            // no authentication actually happened; we're anonymous
            anonymous();
            return;
        }
        RealmInfo realmInfo = oldState.getRealmInfo();
        final RealmIdentity realmIdentity = oldState.getRealmIdentity();
        final AuthorizationIdentity authorizationIdentity = realmIdentity.getAuthorizationIdentity();
        CompleteState newState = new CompleteState(domain.transform(new SecurityIdentity(domain, oldState.getAuthenticationPrincipal(), realmInfo, authorizationIdentity, domain.getCategoryRoleMappers())));
        while (! stateRef.compareAndSet(oldState, newState)) {
            oldState = stateRef.get();
            if (oldState.isDone()) {
                throw ElytronMessages.log.alreadyComplete();
            }
            if (! oldState.isStarted()) {
                throw ElytronMessages.log.noAuthenticationInProgress();
            }
        }
        SecurityRealm.safeHandleRealmEvent(realmInfo.getSecurityRealm(), new RealmSuccessfulAuthenticationEvent(realmIdentity, authorizationIdentity, null, null));
        realmIdentity.dispose();
    }

    /**
     * Determine if authentication was already completed on this context.
     *
     * @return {@code true} if authentication was completed; {@code false} otherwise
     */
    public boolean isDone() {
        return stateRef.get().isDone();
    }

    /**
     * Get the principal associated with the current authentication name.  Only valid during authentication process.
     *
     * @return the principal
     * @throws RealmUnavailableException if the realm is not available
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public Principal getAuthenticationPrincipal() throws RealmUnavailableException {
        return stateRef.get().getAuthenticationPrincipal();
    }

    /**
     * Determine whether a given credential is definitely obtainable, possibly obtainable, or definitely not obtainable.
     *
     * If an authentication identity is established this will be for that identity, otherwise this will be the general
     * level of support advertised by the security domain.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @return the level of support for this credential type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
        SupportLevel supportLevel = stateRef.get().getCredentialAcquireSupport(credentialType, algorithmName);

        return supportLevel != null ? supportLevel : domain.getCredentialAcquireSupport(credentialType, algorithmName);
    }

    /**
     * Determine whether a given credential is definitely obtainable, possibly obtainable, or definitely not obtainable.
     *
     * If an authentication identity is established this will be for that identity, otherwise this will be the general
     * level of support advertised by the security domain.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @return the level of support for this credential type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType) throws RealmUnavailableException {
        return getCredentialAcquireSupport(credentialType, null);
    }

    /**
     * Determine whether a given piece of evidence is definitely verifiable, possibly verifiable, or definitely not verifiable.
     *
     * If an authentication identity is established this will be for that identity, otherwise this will be the general
     * level of support advertised by the security domain.
     *
     * @param evidenceType the evidence type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the evidence type does
     *  not support algorithm names
     * @return the level of support for this credential type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidenceType", evidenceType);
        SupportLevel supportLevel = stateRef.get().getEvidenceVerifySupport(evidenceType, algorithmName);

        return supportLevel != null ? supportLevel : domain.getEvidenceVerifySupport(evidenceType, algorithmName);
    }

    /**
     * Determine whether a given piece of evidence is definitely verifiable, possibly verifiable, or definitely not verifiable.
     *
     * If an authentication identity is established this will be for that identity, otherwise this will be the general
     * level of support advertised by the security domain.
     *
     * @param evidenceType the evidence type class (must not be {@code null})
     * @return the level of support for this credential type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType) throws RealmUnavailableException {
        return getEvidenceVerifySupport(evidenceType, null);
    }

    /**
     * Acquire a credential of the given type.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @param <C> the credential type
     *
     * @return the credential, or {@code null} if the principal has no credential of that type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
        return stateRef.get().getCredential(credentialType, algorithmName);
    }

    /**
     * Acquire a credential of the given type.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param <C> the credential type
     *
     * @return the credential, or {@code null} if the principal has no credential of that type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
        return stateRef.get().getCredential(credentialType, null);
    }

    /**
     * Verify the given evidence.
     *
     * @param evidence the evidence to verify
     *
     * @return {@code true} if verification was successful, {@code false} otherwise
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
        final AtomicReference<State> stateRef = this.stateRef;
        State oldState = stateRef.get();
        // early detection
        if (oldState.isDone()) {
            throw ElytronMessages.log.alreadyComplete();
        }
        final MechanismConfiguration mechanismConfiguration = this.mechanismConfiguration;
        final MechanismRealmConfiguration mechanismRealmConfiguration;
        if (oldState.getId() == REALM_ID) {
            mechanismRealmConfiguration = oldState.getMechanismRealmConfiguration();
        } else if (oldState.getId() == INITIAL_ID) {
            final Collection<String> mechanismRealmNames = mechanismConfiguration.getMechanismRealmNames();
            final Iterator<String> iterator = mechanismRealmNames.iterator();
            if (iterator.hasNext()) {
                // use the default realm
                mechanismRealmConfiguration = mechanismConfiguration.getMechanismRealmConfiguration(iterator.next());
            } else {
                mechanismRealmConfiguration = MechanismRealmConfiguration.NO_REALM;
            }
        } else {
            final boolean verified = stateRef.get().verifyEvidence(evidence);
            return verified && (! (evidence instanceof SecurityIdentityEvidence) || authorize());
        }

        final Principal evidencePrincipal = evidence.getPrincipal();
        if (evidencePrincipal != null) {
            if (evidencePrincipal instanceof AnonymousPrincipal) {
                anonymous();
                return true;
            }
            // We have access to a Principal so set it to cause the state transitions and start again.
            setAuthenticationPrincipal(evidencePrincipal);
            return verifyEvidence(evidence);
        }

        final SecurityDomain domain = this.domain;
        RealmInfo realmInfo = null;
        RealmIdentity realmIdentity = null;
        // no name assigned, no mapping possible; we must iterate the realms
        final Collection<RealmInfo> realmInfos = domain.getRealmInfos();
        for (RealmInfo info : realmInfos) {
            realmIdentity = info.getSecurityRealm().getRealmIdentity(null, null, evidence);
            if (realmIdentity.exists()) {
                realmInfo = info;
                break;
            } else {
                realmIdentity.dispose();
            }
        }
        if (realmInfo == null) {
            // no verification possible, no identity found
            return false;
        }
        assert realmIdentity != null && realmIdentity.exists();
        final Principal resolvedPrincipal = realmIdentity.getRealmIdentityPrincipal();
        if (resolvedPrincipal == null) {
            // we have to have a principal
            realmIdentity.dispose();
            return false;
        }
        boolean ok = false;
        NameAssignedState newState;
        try {
            newState = new NameAssignedState(domain, resolvedPrincipal, realmInfo, realmIdentity, mechanismRealmConfiguration);
            if (! stateRef.compareAndSet(oldState, newState)) {
                // gotta start over, but should happen no more than a theoretical max of 2 times
                return verifyEvidence(evidence);
            }
            ok = true;
        } finally {
            if (! ok) realmIdentity.dispose();
        }
        return newState.verifyEvidence(evidence);
    }

    /**
     * Set the mechanism realm name to be equal to the given name.  If no mechanism realms are configured, the realm
     * name is ignored.
     *
     * @param realmName the selected realm name
     * @throws IllegalStateException if a realm name was already selected or it is too late to choose a realm
     * @throws IllegalArgumentException if the selected realm name was not offered
     */
    public void setMechanismRealmName(String realmName) throws IllegalStateException, IllegalArgumentException {
        final MechanismConfiguration mechanismConfiguration = this.mechanismConfiguration;
        if (mechanismConfiguration.getMechanismRealmNames().isEmpty()) {
            // no realms are configured
            return;
        }
        final MechanismRealmConfiguration configuration = mechanismConfiguration.getMechanismRealmConfiguration(realmName);
        if (configuration == null) {
            throw log.invalidMechRealmSelection(realmName);
        }
        final AtomicReference<State> stateRef = this.stateRef;
        final RealmAssignedState newState = new RealmAssignedState(configuration);
        State oldState;
        do {
            oldState = stateRef.get();
            switch (oldState.getId()) {
                case INITIAL_ID: {
                    // try the CAS
                    break;
                }
                case REALM_ID: {
                    if (configuration == oldState.getMechanismRealmConfiguration()) {
                        // already chosen the same realm
                        return;
                    }
                    // fall thru to exception
                }
                case ASSIGNED_ID:
                case AUTHORIZED_ID: {
                    throw log.mechRealmAlreadySelected();
                }
                case FAILED_ID:
                case COMPLETE_ID: {
                    throw log.alreadyComplete();
                }
                default: {
                    throw Assert.impossibleSwitchCase(oldState.getId());
                }
            }
        } while (! stateRef.compareAndSet(oldState, newState));
    }

    CallbackHandler createCallbackHandler() {
        return new CallbackHandler() {

            @Override
            public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                handleOne(callbacks, 0);
            }

            private void handleOne(final Callback[] callbacks, final int idx) throws IOException, UnsupportedCallbackException {
                if (idx == callbacks.length) {
                    return;
                }
                Callback callback = callbacks[idx];
                if (callback instanceof AnonymousAuthorizationCallback) {
                    // anonymous is always allowed; disable anonymous authentication in the mechanism filters.
                    anonymous();
                    ((AnonymousAuthorizationCallback) callback).setAuthorized(true);
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof AuthorizeCallback) {
                    final AuthorizeCallback authorizeCallback = (AuthorizeCallback) callback;
                    // always re-set the authentication name to ensure it hasn't changed.
                    setAuthenticationName(authorizeCallback.getAuthenticationID());
                    authorizeCallback.setAuthorized(authorize(authorizeCallback.getAuthorizationID()));
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof NameCallback) {
                    // login name
                    final String name = ((NameCallback) callback).getDefaultName();
                    try {
                        setAuthenticationName(name);
                    } catch (Exception e) {
                        throw new IOException(e);
                    }
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof PeerPrincipalCallback) {
                    // login name
                    final Principal principal = ((PeerPrincipalCallback) callback).getPrincipal();
                    try {
                        setAuthenticationPrincipal(principal);
                    } catch (Exception e) {
                        throw new IOException(e);
                    }
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof PasswordCallback) {
                    final PasswordCallback passwordCallback = (PasswordCallback) callback;

                    if (getCredentialAcquireSupport(PasswordCredential.class).mayBeSupported()) {
                        final PasswordCredential credential = getCredential(PasswordCredential.class);

                        if (credential != null) {
                            final TwoWayPassword password = credential.getPassword(TwoWayPassword.class);
                            if (password != null) {
                                final ClearPasswordSpec clearPasswordSpec;
                                try {
                                    final PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                                    clearPasswordSpec = passwordFactory.getKeySpec(password, ClearPasswordSpec.class);
                                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                                    throw new FastUnsupportedCallbackException(callback);
                                }
                                passwordCallback.setPassword(clearPasswordSpec.getEncodedPassword());
                                handleOne(callbacks, idx + 1);
                                return;
                            }
                        }
                        throw new FastUnsupportedCallbackException(callback);
                    }

                    // otherwise just fail out; some mechanisms will try again with different credentials
                    throw new FastUnsupportedCallbackException(callback);

                } else if (callback instanceof CredentialCallback) {
                    if (! stateRef.get().isStarted()) {
                        throw new FastUnsupportedCallbackException(callback);
                    }
                    final CredentialCallback credentialCallback = (CredentialCallback) callback;

                    final Credential credential = getCredential(credentialCallback.getCredentialType(), credentialCallback.getAlgorithm());
                    if (credential != null) {
                        credentialCallback.setCredential(credential);
                        handleOne(callbacks, idx + 1);
                        return;
                    }

                    // otherwise just fail out; some mechanisms will try again with different credentials
                    throw new FastUnsupportedCallbackException(callback);
                } else if (callback instanceof ServerCredentialCallback) {
                    final ServerCredentialCallback serverCredentialCallback = (ServerCredentialCallback) callback;

                    final List<SecurityFactory<Credential>> serverCredentials = mechanismConfiguration.getServerCredentialFactories();
                    for (SecurityFactory<Credential> factory : serverCredentials) {
                        try {
                            final Credential credential = factory.create();
                            if (serverCredentialCallback.isCredentialSupported(credential)) {
                                serverCredentialCallback.setCredential(credential);
                                handleOne(callbacks, idx + 1);
                                return;
                            }
                        } catch (GeneralSecurityException e) {
                            // skip this credential
                        }
                    }

                    throw new FastUnsupportedCallbackException(callback);
                } else if (callback instanceof EvidenceVerifyCallback) {
                    EvidenceVerifyCallback evidenceVerifyCallback = (EvidenceVerifyCallback) callback;

                    evidenceVerifyCallback.setVerified(verifyEvidence(evidenceVerifyCallback.getEvidence()));

                } else if (callback instanceof AuthenticationCompleteCallback) {
                    if (! isDone()) {
                        if (((AuthenticationCompleteCallback) callback).succeeded()) {
                            succeed();
                        } else {
                            fail();
                        }
                    }
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof SocketAddressCallback) {
                    final SocketAddressCallback socketAddressCallback = (SocketAddressCallback) callback;
                    if (socketAddressCallback.getKind() == SocketAddressCallback.Kind.PEER) {
                        // todo: filter by IP address
                    }
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof SecurityIdentityCallback) {
                    ((SecurityIdentityCallback) callback).setSecurityIdentity(getAuthorizedIdentity());
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof AvailableRealmsCallback) {
                    Collection<String> names = mechanismConfiguration.getMechanismRealmNames();
                    if (! names.isEmpty()) {
                        ((AvailableRealmsCallback) callback).setRealmNames(names.toArray(new String[names.size()]));
                    }
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof RealmCallback) {
                    RealmCallback rcb = (RealmCallback) callback;
                    String mechanismRealm = rcb.getText();
                    if (mechanismRealm == null) {
                        mechanismRealm = rcb.getDefaultText();
                    }
                    setMechanismRealmName(mechanismRealm);
                    handleOne(callbacks, idx + 1);
                } else {
                    CallbackUtil.unsupported(callback);
                }
            }

        };
    }

    private static String validatedRewrite(String name, NameRewriter rewriter) {
        String newName = rewriter.rewriteName(name);
        if (newName == null) {
            throw log.invalidName();
        }
        return newName;
    }

    static String rewriteAll(String name, NameRewriter r1, NameRewriter r2, NameRewriter r3) {
        if (r1 != null) {
            return validatedRewrite(name, r1);
        }
        if (r2 != null) {
            return validatedRewrite(name, r2);
        }
        if (r3 != null) {
            return validatedRewrite(name, r3);
        }
        return name;
    }

    static String mapAll(String name, RealmMapper r1, RealmMapper r2, RealmMapper r3, String defaultRealmName) {
        if (r1 != null) {
            return mapRealmName(name, r1, defaultRealmName);
        }
        if (r2 != null) {
            return mapRealmName(name, r2, defaultRealmName);
        }
        if (r3 != null) {
            return mapRealmName(name, r3, defaultRealmName);
        }
        return defaultRealmName;
    }

    private static String mapRealmName(String name, RealmMapper realmMapper, String defaultRealmName) {
        String realmName = realmMapper.getRealmMapping(name, null, null);
        return realmName != null ? realmName : defaultRealmName;
    }

    private static final int INITIAL_ID = 0;
    private static final int FAILED_ID = 1;
    private static final int REALM_ID = 2;
    private static final int ASSIGNED_ID = 3;
    private static final int AUTHORIZED_ID = 4;
    private static final int COMPLETE_ID = 5;

    abstract static class State {
        abstract int getId();

        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        SecurityIdentity getAuthorizedIdentity() {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        Principal getAuthenticationPrincipal() {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
            return null;
        }

        SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            return null;
        }

        <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        RealmInfo getRealmInfo() {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        RealmIdentity getRealmIdentity() {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        SecurityDomain getSecurityDomain() {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        abstract boolean isDone();

        abstract boolean isStarted();
    }

    static final class SimpleState extends State {
        private final int id;
        private final boolean done;
        private final boolean started;

        SimpleState(final int id, final boolean done, final boolean started) {
            this.id = id;
            this.done = done;
            this.started = started;
        }

        @Override
        public int getId() {
            return id;
        }

        @Override
        boolean isDone() {
            return done;
        }

        @Override
        boolean isStarted() {
            return started;
        }

    }

    static final class CompleteState extends State {
        private final SecurityIdentity identity;

        public CompleteState(final SecurityIdentity identity) {
            this.identity = identity;
        }

        @Override
        int getId() {
            return COMPLETE_ID;
        }

        @Override
        SecurityIdentity getAuthorizedIdentity() {
            return identity;
        }

        @Override
        boolean isDone() {
            return true;
        }

        @Override
        boolean isStarted() {
            return true;
        }
    }

    static final class AuthorizedState extends State {
        private final SecurityIdentity securityIdentity;
        private final Principal authenticationPrincipal;
        private final RealmInfo realmInfo;
        private final RealmIdentity realmIdentity;
        private final MechanismRealmConfiguration mechanismRealmConfiguration;

        AuthorizedState(final SecurityIdentity securityIdentity, final Principal authenticationPrincipal, final RealmInfo realmInfo, final RealmIdentity realmIdentity, final MechanismRealmConfiguration mechanismRealmConfiguration) {
            this.securityIdentity = securityIdentity;
            this.authenticationPrincipal = authenticationPrincipal;
            this.realmInfo = realmInfo;
            this.realmIdentity = realmIdentity;
            this.mechanismRealmConfiguration = mechanismRealmConfiguration;
        }

        @Override
        int getId() {
            return AUTHORIZED_ID;
        }

        @Override
        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            return mechanismRealmConfiguration;
        }

        @Override
        SecurityIdentity getAuthorizedIdentity() {
            return securityIdentity;
        }

        @Override
        Principal getAuthenticationPrincipal() {
            return authenticationPrincipal;
        }

        @Override
        SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getCredentialAcquireSupport(credentialType, algorithmName);
        }

        @Override
        SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return SecurityIdentityEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : realmIdentity.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        <C extends Credential> C getCredential(final Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getCredential(credentialType, algorithmName);
        }

        @Override
        boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            return checkEvidenceTrusted(realmIdentity, getSecurityDomain(), evidence) || realmIdentity.verifyEvidence(evidence);
        }

        @Override
        RealmInfo getRealmInfo() {
            return realmInfo;
        }

        @Override
        RealmIdentity getRealmIdentity() {
            return realmIdentity;
        }

        @Override
        SecurityDomain getSecurityDomain() {
            return securityIdentity.getSecurityDomain();
        }

        @Override
        boolean isDone() {
            return false;
        }

        @Override
        boolean isStarted() {
            return true;
        }
    }

    static final class NameAssignedState extends State {
        private final SecurityDomain domain;
        private final Principal authenticationPrincipal;
        private final RealmInfo realmInfo;
        private final RealmIdentity realmIdentity;
        private final MechanismRealmConfiguration mechanismRealmConfiguration;

        NameAssignedState(final SecurityDomain domain, final Principal authenticationPrincipal, final RealmInfo realmInfo, final RealmIdentity realmIdentity, final MechanismRealmConfiguration mechanismRealmConfiguration) {
            this.domain = domain;
            this.authenticationPrincipal = authenticationPrincipal;
            this.realmInfo = realmInfo;
            this.realmIdentity = realmIdentity;
            this.mechanismRealmConfiguration = mechanismRealmConfiguration;
        }

        @Override
        int getId() {
            return ASSIGNED_ID;
        }

        @Override
        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            return mechanismRealmConfiguration;
        }

        @Override
        Principal getAuthenticationPrincipal() {
            return authenticationPrincipal;
        }

        @Override
        SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getCredentialAcquireSupport(credentialType, algorithmName);
        }

        @Override
        SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return SecurityIdentityEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : realmIdentity.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getCredential(credentialType, algorithmName);
        }

        @Override
        boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            return checkEvidenceTrusted(realmIdentity, domain, evidence) || realmIdentity.verifyEvidence(evidence);
        }

        @Override
        RealmInfo getRealmInfo() {
            return realmInfo;
        }

        @Override
        RealmIdentity getRealmIdentity() {
            return realmIdentity;
        }

        @Override
        SecurityDomain getSecurityDomain() {
            return domain;
        }

        @Override
        boolean isDone() {
            return false;
        }

        @Override
        boolean isStarted() {
            return true;
        }
    }

    static final class RealmAssignedState extends State {
        private final MechanismRealmConfiguration mechanismRealmConfiguration;

        RealmAssignedState(final MechanismRealmConfiguration mechanismRealmConfiguration) {
            this.mechanismRealmConfiguration = mechanismRealmConfiguration;
        }

        @Override
        int getId() {
            return REALM_ID;
        }

        @Override
        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            return mechanismRealmConfiguration;
        }

        @Override
        boolean isDone() {
            return false;
        }

        @Override
        boolean isStarted() {
            return true;
        }
    }

    private static final SimpleState INITIAL = new SimpleState(INITIAL_ID, false, false);
    private static final SimpleState FAILED = new SimpleState(FAILED_ID, true, true);

    /**
     * Determine if the given evidence can be trusted in lieu of verifying or acquiring a credential.
     *
     * @param realmIdentity the current realm identity
     * @param domain the current domain
     * @param evidence the evidence to check (must not be {@code null})
     * @return {@code true} if the given evidence can be trusted, {@code false} otherwise
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    static boolean checkEvidenceTrusted(final RealmIdentity realmIdentity, final SecurityDomain domain, final Evidence evidence) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidence", evidence);
        if (! realmIdentity.exists()) {
            return false;
        }
        if (evidence instanceof SecurityIdentityEvidence) {
            // Check that the given security identity evidence either corresponds to the same realm that created the
            // current authentication identity or it corresponds to a domain that is trusted by the current domain
            final SecurityIdentity evidenceIdentity = ((SecurityIdentityEvidence) evidence).getSecurityIdentity();
            final RealmInfo evidenceRealmInfo = evidenceIdentity.getRealmInfo();
            final SecurityRealm evidenceSecurityRealm = evidenceRealmInfo.getSecurityRealm();
            final SecurityDomain evidenceSecurityDomain = evidenceIdentity.getSecurityDomain();
            return realmIdentity.createdBySecurityRealm(evidenceSecurityRealm) || domain.trustsDomain(evidenceSecurityDomain);
        }
        return false;
    }
}
