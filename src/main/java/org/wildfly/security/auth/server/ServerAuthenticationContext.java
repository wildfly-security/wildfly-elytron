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
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.AnonymousAuthorizationCallback;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.CredentialParameterCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.PeerPrincipalCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.callback.SocketAddressCallback;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.permission.RunAsPrincipalPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
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
        name = validatedRewrite(name, mechanismConfiguration.getPreRealmRewriter());
        name = validatedRewrite(name, mechanismRealmConfiguration.getPreRealmRewriter());
        name = validatedRewrite(name, domain.getPreRealmRewriter());
        // principal *must* be captured at this point
        final NamePrincipal principal = new NamePrincipal(name);
        name = validatedRewrite(name, mechanismConfiguration.getPostRealmRewriter());
        name = validatedRewrite(name, mechanismRealmConfiguration.getPostRealmRewriter());
        name = validatedRewrite(name, domain.getPostRealmRewriter());
        final RealmInfo realmInfo = domain.getRealmInfo(domain.mapRealmName(name));
        name = validatedRewrite(name, realmInfo.getNameRewriter());
        name = validatedRewrite(name, mechanismConfiguration.getFinalRewriter());
        name = validatedRewrite(name, mechanismRealmConfiguration.getFinalRewriter());
        // name should remain
        if (oldState.getId() == ASSIGNED_ID) {
            if (! oldState.getAuthenticationPrincipal().getName().equals(name) || oldState.getMechanismRealmConfiguration() != mechanismRealmConfiguration) {
                throw log.nameAlreadySet();
            }
            // no further action needed
            return;
        }
        final SecurityRealm securityRealm = realmInfo.getSecurityRealm();
        final RealmIdentity realmIdentity = securityRealm.createRealmIdentity(name);
        boolean ok = false;
        try {
            NameAssignedState newState = new NameAssignedState(principal, realmInfo, realmIdentity, mechanismRealmConfiguration);
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
        name = domain.getPreRealmRewriter().rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        String realmName = domain.mapRealmName(name);
        RealmInfo realmInfo = domain.getRealmInfo(realmName);
        name = domain.getPostRealmRewriter().rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        name = realmInfo.getNameRewriter().rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }
        return stateRef.get().getAuthenticationPrincipal().getName().equals(name);
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
        if (oldState.getId() == ASSIGNED_ID) {
            oldState.getRealmIdentity().dispose();
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
        if (/* TODO: test suite is broken */ false && ! realmIdentity.exists()) {
            return false;
        }

        final RealmInfo realmInfo = oldState.getRealmInfo();
        final Principal authenticationPrincipal = oldState.getAuthenticationPrincipal();

        final AuthorizationIdentity authorizationIdentity = realmIdentity.getAuthorizationIdentity();

        final SecurityIdentity securityIdentity = new SecurityIdentity(domain, authenticationPrincipal, realmInfo, authorizationIdentity, domain.getCategoryRoleMappers());
        if (/* TODO: tests need major refitting */ true || securityIdentity.getPermissions().implies(new LoginPermission())) {
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
            return true;
        } else {
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
            name = validatedRewrite(name, mechanismConfiguration.getPreRealmRewriter());
            name = validatedRewrite(name, mechanismRealmConfiguration.getPreRealmRewriter());
            name = validatedRewrite(name, domain.getPreRealmRewriter());
            // pause here and see if we're really authorizing a new identity
            // principal *must* be captured at this point
            final NamePrincipal principal = new NamePrincipal(name);
            if (oldState.getAuthenticationPrincipal().equals(principal)) {
                // it's the same identity; just succeed as we are already authorized per above
                succeed();
                return true;
            }

            // check the run-as permission on the old identity
            if (! oldState.getAuthorizedIdentity().getPermissions().implies(new RunAsPrincipalPermission(principal.getName()))) {
                return false;
            }

            // continue rewriting to locate the new authorization identity
            name = validatedRewrite(name, mechanismConfiguration.getPostRealmRewriter());
            name = validatedRewrite(name, mechanismRealmConfiguration.getPostRealmRewriter());
            name = validatedRewrite(name, domain.getPostRealmRewriter());
            final RealmInfo realmInfo = domain.getRealmInfo(domain.mapRealmName(name));
            name = validatedRewrite(name, realmInfo.getNameRewriter());
            name = validatedRewrite(name, mechanismConfiguration.getFinalRewriter());
            name = validatedRewrite(name, mechanismRealmConfiguration.getFinalRewriter());

            // now construct the new identity
            final SecurityRealm securityRealm = realmInfo.getSecurityRealm();
            final RealmIdentity realmIdentity = securityRealm.createRealmIdentity(name);
            boolean ok = false;
            try {
                if (/* TODO: test suite is broken */ false && ! realmIdentity.exists()) {
                    return false;
                }
                final AuthorizationIdentity authorizationIdentity = realmIdentity.getAuthorizationIdentity();
                final SecurityIdentity newIdentity = new SecurityIdentity(domain, principal, realmInfo, authorizationIdentity, domain.getCategoryRoleMappers());

                // make sure the new identity is authorized
                if (/* TODO: tests need major refitting */ false && ! newIdentity.getPermissions().implies(new LoginPermission())) {
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
        final AuthorizationIdentity authorizationIdentity = oldState.getRealmIdentity().getAuthorizationIdentity();
        CompleteState newState = new CompleteState(new SecurityIdentity(domain, oldState.getAuthenticationPrincipal(), realmInfo, authorizationIdentity, domain.getCategoryRoleMappers()));
        while (! stateRef.compareAndSet(oldState, newState)) {
            oldState = stateRef.get();
            if (oldState.isDone()) {
                throw ElytronMessages.log.alreadyComplete();
            }
            if (! oldState.isStarted()) {
                throw ElytronMessages.log.noAuthenticationInProgress();
            }
        }
        oldState.getRealmIdentity().dispose();
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
     * Determine whether a given credential is definitely obtainable, possibly obtainable, or definitely not obtainable for
     * the current authentication identity.
     *
     * @param credentialName the credential name
     * @return the level of support for this credential type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public SupportLevel getCredentialAcquireSupport(String credentialName) throws RealmUnavailableException {
        return stateRef.get().getCredentialAcquireSupport(credentialName);
    }

    /**
     * Determine whether a given piece of evidence is definitely verifiable, possibly verifiable, or definitely not verifiable for
     * the current authentication identity.
     *
     * @param credentialName the credential name
     * @return the level of support for this credential type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public SupportLevel getEvidenceVerifySupport(String credentialName) throws RealmUnavailableException {
        return stateRef.get().getEvidenceVerifySupport(credentialName);
    }

    /**
     * Acquire a credential of the given type.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialName the credential name
     * @param credentialType the credential type class
     * @param <C> the credential type
     *
     * @return the credential, or {@code null} if the principal has no credential of that type
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public <C extends Credential> C getCredential(String credentialName, Class<C> credentialType) throws RealmUnavailableException {
        return stateRef.get().getCredential(credentialName, credentialType);
    }

    /**
     * Acquire a credential after resolving the List of possible credential names along with the map of supported credential types with supported algorithms against
     * the credentials actually available.
     *
     * @param credentialNames the list of credential names to query
     * @param supportedTypesWithAlgorithms the Map of supported credential types along with the supported algorithms for each of those types.
     *
     * @return the credential, or {@code null} if a match was not possible.
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */

    public Credential getCredential(List<String> credentialNames, Map<Class<? extends Credential>, Set<String>> supportedTypesWithAlgorithms) throws RealmUnavailableException {
        return stateRef.get().getCredential(credentialNames, supportedTypesWithAlgorithms);
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
    public boolean verifyEvidence(String credentialName, Evidence evidence) throws RealmUnavailableException {
        return stateRef.get().verifyEvidence(credentialName, evidence);
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

    List<String> getCredentialNames() {
        State state = stateRef.get();
        final MechanismRealmConfiguration mechanismRealmConfiguration = state.getMechanismRealmConfiguration();
        if (mechanismRealmConfiguration != null) {
            final Supplier<List<String>> supplier = mechanismRealmConfiguration.getCredentialNameSupplier();
            if (supplier != null) {
                return supplier.get();
            }
        }
        return mechanismConfiguration.getCredentialNameSupplier().get();
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

                    List<String> credentialNames = getCredentialNames();
                    for (String credentialName : credentialNames) {
                        if (getCredentialAcquireSupport(credentialName).mayBeSupported()) { // TODO maybe???
                            final PasswordCredential credential = getCredential(credentialName, PasswordCredential.class);

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
                    }

                    // otherwise just fail out; some mechanisms will try again with different credentials
                    throw new FastUnsupportedCallbackException(callback);

                } else if (callback instanceof CredentialCallback) {
                    if (!stateRef.get().isStarted()) {
                        throw new FastUnsupportedCallbackException(callback);
                    }
                    final CredentialCallback credentialCallback = (CredentialCallback) callback;

                    List<String> credentialNames = getCredentialNames();

                    final Credential credential = getCredential(credentialNames, credentialCallback.getSupportedTypesWithAlgorithms());
                    if (credential != null) {
                        credentialCallback.setCredential(credential);
                        handleOne(callbacks, idx + 1);
                        return;
                    }

                    // otherwise just fail out; some mechanisms will try again with different credentials
                    throw new FastUnsupportedCallbackException(callback);

                } else if (callback instanceof EvidenceVerifyCallback) {
                    EvidenceVerifyCallback evidenceVerifyCallback = (EvidenceVerifyCallback) callback;

                    List<String> credentialNames = getCredentialNames();
                    for (String credentialName : credentialNames) {
                        evidenceVerifyCallback.setVerified(verifyEvidence(credentialName, evidenceVerifyCallback.getEvidence()));
                    }

                } else if (callback instanceof CredentialParameterCallback) {
                    // ignore for now
                    handleOne(callbacks, idx + 1);
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

        SupportLevel getCredentialAcquireSupport(final String credentialName) throws RealmUnavailableException {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        SupportLevel getEvidenceVerifySupport(final String credentialName) throws RealmUnavailableException {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        <C extends Credential> C getCredential(final String credentialName, final Class<C> credentialType) throws RealmUnavailableException {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        Credential getCredential(final List<String> credentialNames, final Map<Class<? extends Credential>, Set<String>> supportedTypesWithAlgorithms) throws RealmUnavailableException {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        boolean verifyEvidence(final String credentialName, final Evidence evidence) throws RealmUnavailableException {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        RealmInfo getRealmInfo() {
            throw ElytronMessages.log.noAuthenticationInProgress();
        }

        RealmIdentity getRealmIdentity() {
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
        SupportLevel getCredentialAcquireSupport(final String credentialName) throws RealmUnavailableException {
            return realmIdentity.getCredentialAcquireSupport(credentialName);
        }

        @Override
        SupportLevel getEvidenceVerifySupport(final String credentialName) throws RealmUnavailableException {
            return realmIdentity.getEvidenceVerifySupport(credentialName);
        }

        @Override
        <C extends Credential> C getCredential(final String credentialName, final Class<C> credentialType) throws RealmUnavailableException {
            return realmIdentity.getCredential(credentialName, credentialType);
        }

        @Override
        Credential getCredential(List<String> credentialNames, Map<Class<? extends Credential>, Set<String>> supportedTypesWithAlgorithms) throws RealmUnavailableException {
            return realmIdentity.getCredential(credentialNames, supportedTypesWithAlgorithms);
        }

        @Override
        boolean verifyEvidence(final String credentialName, final Evidence evidence) throws RealmUnavailableException {
            return realmIdentity.verifyEvidence(credentialName, evidence);
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
        boolean isDone() {
            return false;
        }

        @Override
        boolean isStarted() {
            return true;
        }
    }

    static final class NameAssignedState extends State {
        private final Principal authenticationPrincipal;
        private final RealmInfo realmInfo;
        private final RealmIdentity realmIdentity;
        private final MechanismRealmConfiguration mechanismRealmConfiguration;

        NameAssignedState(final Principal authenticationPrincipal, final RealmInfo realmInfo, final RealmIdentity realmIdentity, final MechanismRealmConfiguration mechanismRealmConfiguration) {
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
        SupportLevel getCredentialAcquireSupport(final String credentialName) throws RealmUnavailableException {
            return realmIdentity.getCredentialAcquireSupport(credentialName);
        }

        @Override
        SupportLevel getEvidenceVerifySupport(final String credentialName) throws RealmUnavailableException {
            return realmIdentity.getEvidenceVerifySupport(credentialName);
        }

        @Override
        <C extends Credential> C getCredential(final String credentialName, final Class<C> credentialType) throws RealmUnavailableException {
            return realmIdentity.getCredential(credentialName, credentialType);
        }

        @Override
        Credential getCredential(List<String> credentialNames, Map<Class<? extends Credential>, Set<String>> supportedTypesWithAlgorithms) throws RealmUnavailableException {
            return realmIdentity.getCredential(credentialNames, supportedTypesWithAlgorithms);
        }

        @Override
        boolean verifyEvidence(final String credentialName, final Evidence evidence) throws RealmUnavailableException {
            return realmIdentity.verifyEvidence(credentialName, evidence);
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
}
