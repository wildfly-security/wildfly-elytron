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
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.wildfly.common.Assert;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.AnonymousAuthorizationCallback;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.PeerPrincipalCallback;
import org.wildfly.security.auth.callback.SSLSessionAuthorizationCallback;
import org.wildfly.security.auth.callback.SecurityIdentityCallback;
import org.wildfly.security.auth.callback.ServerCredentialCallback;
import org.wildfly.security.auth.callback.ServerNameCallback;
import org.wildfly.security.auth.callback.SocketAddressCallback;
import org.wildfly.security.auth.client.PeerIdentity;
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
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.ssl.SSLUtils;
import org.wildfly.security.x500.X500;

/**
 * Server-side authentication context.  Instances of this class are used to preform all authentication and re-authorization
 * operations that involve the usage of an identity in a {@linkplain SecurityDomain security domain}.
 * <p>
 * There are various effective states, described as follows:
 * <ul>
 *     <li>
 *         The <em>unassigned</em> states:
 *         <ul>
 *             <li><em>Initial</em></li>
 *             <li><em>Realm-assigned</em></li>
 *         </ul>
 *     </li>
 *     <li>The <em>assigned</em> state</li>
 *     <li>
 *         The <em>authorized</em> states:
 *         <ul>
 *             <li><em>Anonymous-authorized</em></li>
 *             <li><em>Authorized</em></li>
 *             <li><em>Authorized-authenticated</em></li>
 *         </ul>
 *     </li>
 *     <li>
 *         The <em>terminal</em> states:
 *         <ul>
 *             <li><em>Complete</em></li>
 *             <li><em>Failed</em></li>
 *         </ul>
 *     </li>
 * </ul>
 *
 * <p>
 * When an instance of this class is first constructed, it is in the <em>initial</em> state.  In this state, the context
 * retains an <em>captured {@linkplain SecurityIdentity identity}</em> and an optional <em>{@linkplain MechanismConfiguration mechanism configuration}</em>.
 * The <em>captured identity</em> may be used for various context-sensitive authorization decisions.  The <em>mechanism
 * configuration</em> is used to associate an authentication mechanism-specific configuration, including rewriters,
 * {@linkplain MechanismRealmConfiguration mechanism realms}, server credential factories, and more.
 * <p>
 * When an authentication mechanism is "realm-aware" (that is, it has a notion of realms that is specific to that particular
 * authentication mechanism, e.g. <a href="https://tools.ietf.org/html/rfc2831">the DIGEST-MD5 SASL mechanism</a>), it
 * is necessary for the mechanism to relay the realm selection.  This is done by way of the {@link #setMechanismRealmName(String) setMechanismRealmName()}
 * method.  Calling this method in the <em>initial</em> state causes a transition to the <em>realm-assigned</em> state,
 * in which the method may be reinvoked idempotently as long as it is called with the same name (calling the method with
 * a different name will result in an exception).
 * <p>
 * The <em>realm-assigned</em> state is nearly identical to the <em>initial</em> state, except that from this state, the
 * mechanism realm-specific configuration is applied to all subsequent operation.
 * <p>
 * From these <em>unassigned</em> states, several possible actions may be taken, depending on the necessary progression
 * of the authentication:
 * <ul>
 *     <li>
 *         A <em>name</em> may be assigned by way of the {@link #setAuthenticationName(String)} method.  The name is
 *         {@linkplain NameRewriter rewritten} and {@linkplain RealmMapper mapped to a realm} according to the
 *         domain settings, the <em>mechanism configuration</em>, and/or the <em>mechanism realm configuration</em>.  The
 *         <em>{@linkplain SecurityRealm realm}</em> that is the resultant target of the mapping is queried for a
 *         <em>{@linkplain RealmIdentity realm identity}</em>.  The <em>realm identity</em> may or may not be
 *         existent; this status will affect the outcome of certain operations in subsequent states (as described below).
 *         After the <em>realm identity</em> is selected, any final rewrite operations which are configured are applied,
 *         and the resultant name is transformed into a {@link NamePrincipal}, and associated as the
 *         <em>{@linkplain #getAuthenticationPrincipal() authentication principal}</em> which may subsequently be queried.
 *     </li>
 *     <li>
 *         A <em>principal</em> may be assigned using the {@link #setAuthenticationPrincipal(Principal)} method.  The
 *         principal is {@linkplain PrincipalDecoder decoded} according to the configuration of the security domain (see
 *         the method documentation for input requirements and failure conditions).  Once a name is decoded from the
 *         principal, it is assigned as described above.
 *     </li>
 *     <li>
 *         A unit of <em>{@linkplain Evidence evidence}</em> may be verified.  This is mostly described below in the
 *         context of the <em>assigned</em> state, but with the important distinction the evidence is first examined
 *         to locate the corresponding evidence, in the following steps:
 *         <ul>
 *             <li>
 *                 Firstly, the evidence is examined to determine whether it {@linkplain Evidence#getPrincipal() contains a principal}.
 *                 If so, the principal name is first established using the procedure described above, and then the normal
 *                 evidence verification procedure described below commences.
 *             </li>
 *             <li>
 *                 Secondly, the evidence is socialized to each <em>realm</em> in turn, to see if a realm can recognize
 *                 and {@linkplain SecurityRealm#getRealmIdentity(IdentityLocator) locate} an identity based on
 *                 the evidence.  If so, the <em>realm identity</em> is {@linkplain RealmIdentity#getRealmIdentityPrincipal() queried}
 *                 for an authentication principal, which is then decoded and established as described above.  Once this
 *                 is done successfully, the evidence verification procedure described below commences.
 *             </li>
 *             <li>Finally, if none of these steps succeeds, the verification fails and no state transition occurs.</li>
 *         </ul>
 *     </li>
 *     <li>
 *         An <em>identity</em> may be {@linkplain #importIdentity(SecurityIdentity) imported}.  In this process,
 *         a {@link SecurityIdentity} instance is examined to determine whether it can be used to complete an implicit
 *         authentication operation which would yield an <em>authorized identity</em>.  The {@code SecurityIdentity} may
 *         be from the same <em>domain</em> or from a different one.
 *         <p>
 *         If the <em>identity</em> being imported is from the same security domain as this context, then the <em>identity</em>
 *         is implicitly <em>authorized</em> for usage, entering the <em>authorized</em> state described below.
 *         <p>
 *         If the <em>identity</em> being imported is not from the same security domain, then the principal is extracted
 *         from the identity and used to assign a <em>realm identity</em> in the same manner as {@link #setAuthenticationPrincipal(Principal)}.
 *         The <em>domain</em> is then {@linkplain SecurityDomain.Builder#setTrustedSecurityDomainPredicate(Predicate) queried}
 *         to determine whether the target identity's source <em>domain</em> is <em>trusted</em>.  If so, a normal
 *         <em>authorization</em> is carried out as described below for the <em>assigned</em> state, resulting in an
 *         <em>authorized-authenticated</em> state.  If not, then the <em>realm</em> of the <em>realm identity</em> is
 *         compared against the <em>realm</em> of the <em>identity</em> being imported.  If they are the same, the
 *         identity is imported and a normal <em>authorization</em> is carried out as described below.
 *     </li>
 *     <li>
 *         An <em>anonymous authorization</em> may be carried out by way of the {@link #authorizeAnonymous()} method.
 *         If the <em>{@linkplain SecurityDomain#getAnonymousSecurityIdentity() anonymous identity}</em> has the
 *         {@link LoginPermission} granted to it, the context will transition into the <em>anonymous-authorized</em>
 *         state; otherwise no state transition occurs.
 *     </li>
 *     <li>
 *         An <em>external authorization</em> may be carried out using the {@link #authorize()} method.  The
 *         <em>captured identity</em> (which may be <em>anonymous</em>) is queried for the presence of the
 *         {@link LoginPermission}; if present, the context will transition into the <em>authorized</em> or
 *         <em>anonymous-authorized</em> state (depending on whether the <em>captured identity</em> is <em>anonymous</em>);
 *         otherwise no state transition occurs.
 *     </li>
 *     <li>
 *         An <em>external run-as authorization</em> may be carried out using the {@link #authorize(String)} method.
 *         First, the given name is <em>rewritten</em> in the same manner as the {@link #setAuthenticationName(String)}
 *         method.  Then, the <em>captured identity</em> (which may be <em>anonymous</em>) is queried for the presence of a
 *         {@link RunAsPrincipalPermission} for the target name.  If present, the <em>authentication name</em> is assigned
 *         as described above, and the resultant <em>realm identity</em> is queried for {@link LoginPermission}.  If present,
 *         the context will transition to the <em>authorized-authenticated</em> state.  If any step fails, no state transition
 *         occurs.
 *     </li>
 *     <li>
 *         The authentication may be <em>failed</em> by way of the {@link #fail()} method.  This method will dispose
 *         of all authentication resources and transition to the <em>failed</em> state.
 *     </li>
 * </ul>
 * <p>
 * In the <em>name-assigned</em> (or, for brevity, <em>assigned</em>) state, the following actions may be performed:
 * <ul>
 *     <li>
 *         A name or principal may be assigned as above, however the resultant <em>decoded</em> and <em>rewritten</em> name
 *         and <em>realm identity</em> must be identical to the previously selected name and identity.
 *     </li>
 *     <li>
 *         <em>Evidence</em> may be verified.  The <em>realm identity</em> is queried directly and no state transitions
 *         will occur.  Evidence verification will fail if the evidence has an <em>evidence principal</em> which does
 *         not result in the same <em>realm identity</em> as the current one after <em>decoding</em> and <em>rewriting</em>.
 *     </li>
 *     <li>
 *         An <em>authorization</em> may be performed via the {@link #authorize()} method.  If the selected <em>realm identity</em>
 *         possesses the {@link LoginPermission}, then the context transitions to the <em>authorized-authenticated</em> state,
 *         otherwise no state transition occurs.
 *     </li>
 *     <li>
 *         A <em>run-as authorization</em> may be performed via the {@link #authorize(String)} method.
 *         First, the given name is <em>rewritten</em> in the same manner as the {@link #setAuthenticationName(String)} method.
 *         The current identity is then <em>authorized</em> as described above, and then the <em>authorized identity</em>
 *         is tested for a {@link RunAsPrincipalPermission} for the <em>rewritten</em> target name.  If authorized,
 *         the context transitions to the <em>authorized</em> state for the <em>realm identity</em> corresponding to the
 *         <em>rewritten</em> name; otherwise no state transition occurs.
 *     </li>
 *     <li>
 *         The authentication may be <em>failed</em> by way of the {@link #fail()} method.  This method will dispose
 *         of all authentication resources and transition to the <em>failed</em> state.
 *     </li>
 * </ul>
 * <p>
 * There are three states related to authorization: the <em>anonymous-authorized</em> state, the <em>authorized</em> state,
 * and the <em>authorized-authenticated</em> state.  In all three states, the following actions may be taken:
 * <ul>
 *     <li>
 *         As above, a name or principal may be assigned so long as it matches the existing identity.  In particular,
 *         for the <em>anonymous-authorized</em> state, all names are rejected, and only the {@linkplain AnonymousPrincipal anonymous principal}
 *         is accepted.
 *     </li>
 *     <li>
 *         An <em>authorization</em> may be performed via the {@link #authorize()} method.  Since the identity is
 *         always authorized, this is generally a no-op.
 *     </li>
 *     <li>
 *         A <em>run-as authorization</em> may be performed via the {@link #authorize(String)} method.  The given
 *         name is <em>rewritten</em> as previously described, and then the <em>authorized identity</em>
 *         is tested for a {@link RunAsPrincipalPermission} for the <em>rewritten</em> target name.  If authorized,
 *         the context transitions to the <em>authorized</em> state for the <em>realm identity</em> corresponding to the
 *         <em>rewritten</em> name; otherwise no state transition occurs.
 *     </li>
 *     <li>
 *         The authentication may be <em>completed</em> by way of the {@link #succeed()} method.  This method will
 *         dispose of all authentication resources and transition to the <em>complete</em> state.
 *     </li>
 *     <li>
 *         The authentication may be <em>failed</em> by way of the {@link #fail()} method.  This method will dispose
 *         of all authentication resources and transition to the <em>failed</em> state.
 *     </li>
 * </ul>
 * The <em>authorized-authenticated</em> state has the additional capability of verifying credentials as described above for
 * the <em>assigned</em> state.
 * <p>
 * The <em>complete</em> state has only one capability: the retrieval of the final <em>authorized identity</em> by way
 * of the {@link #getAuthorizedIdentity()} method.
 * <p>
 * The <em>failed</em> state has no capabilities and retains no reference to any identities or objects used during
 * authentication.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class ServerAuthenticationContext {

    private final AtomicReference<State> stateRef;

    ServerAuthenticationContext(final SecurityDomain domain, final MechanismConfiguration mechanismConfiguration) {
        this(domain.getCurrentSecurityIdentity(), mechanismConfiguration);
    }

    ServerAuthenticationContext(final SecurityIdentity capturedIdentity, final MechanismConfiguration mechanismConfiguration) {
        stateRef = new AtomicReference<>(new InitialState(capturedIdentity, mechanismConfiguration));
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
    public boolean authorizeAnonymous() throws IllegalStateException {
        return stateRef.get().authorizeAnonymous(true);
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
        stateRef.get().setName(name);
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
        stateRef.get().setPrincipal(principal);
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
        return stateRef.get().isSameName(name);
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
        return stateRef.get().isSamePrincipal(principal);
    }

    /**
     * Determine if the current authentication identity actually exists in the realm.
     *
     * @return {@code true} if the identity exists, {@code false} otherwise
     * @throws RealmUnavailableException if the realm failed to access the identity
     * @throws IllegalStateException if there is no authentication name set
     */
    public boolean exists() throws RealmUnavailableException, IllegalStateException {
        return stateRef.get().getRealmIdentity().exists();
    }

    /**
     * Mark this authentication as "failed".  The context cannot be used after this method is called.
     *
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public void fail() throws IllegalStateException {
        stateRef.get().fail();
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
        return authorize(true);
    }

    boolean authorize(boolean requireLoginPermission) throws RealmUnavailableException, IllegalStateException {
        return stateRef.get().authorize(requireLoginPermission);
    }

    /**
     * Attempt to authorize a change to a new user (possibly including an authentication attempt).  If the authorization
     * is successful, {@code true} is returned and the context is placed in the "authorized" state with the new authorization
     * identity.  If the authorization fails, {@code false} is returned and the state of the context is unchanged.
     *
     * @param name the authorization name
     * @return {@code true} if the authorization succeeded, {@code false} otherwise
     * @throws IllegalArgumentException if the name is syntactically invalid
     * @throws RealmUnavailableException if the realm is not available
     * @throws IllegalStateException if the authentication name was not set or authentication was already complete
     */
    public boolean authorize(String name) throws IllegalArgumentException, RealmUnavailableException, IllegalStateException {
        return authorize(name, true);
    }

    boolean authorize(String name, boolean authorizeRunAs) throws IllegalArgumentException, RealmUnavailableException, IllegalStateException {
        Assert.checkNotNullParam("name", name);
        return stateRef.get().authorize(name, authorizeRunAs);
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
        stateRef.get().succeed();
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
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    public Principal getAuthenticationPrincipal() {
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
        Assert.checkNotNullParam("credentialType", credentialType);
        return stateRef.get().getCredentialAcquireSupport(credentialType, algorithmName);
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
        Assert.checkNotNullParam("credentialType", credentialType);
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
        return stateRef.get().getEvidenceVerifySupport(evidenceType, algorithmName);
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
        Assert.checkNotNullParam("evidenceType", evidenceType);
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
        Assert.checkNotNullParam("credentialType", credentialType);
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
        Assert.checkNotNullParam("credentialType", credentialType);
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
        Assert.checkNotNullParam("evidence", evidence);
        return stateRef.get().verifyEvidence(evidence);
    }

    /**
     * Attempt to import the given security identity as a trusted identity.  If this method returns {@code true},
     * the context will be in an authorized state, and the new identity can be retrieved.
     *
     * @param identity the identity to import (must not be {@code null})
     * @return {@code true} if the identity is authorized, {@code false} otherwise
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    public boolean importIdentity(SecurityIdentity identity) throws RealmUnavailableException {
        Assert.checkNotNullParam("identity", identity);
        return stateRef.get().importIdentity(identity);
    }

    /**
     * Set the server name for the current authentication attempt, if a server specific mechanism configuration is available
     * this will be used instead of the default configuration.
     *
     * The server name needs to be set before the mechanism realm name is set.
     *
     * @param serverName
     * @throws IllegalStateException
     * @throws IllegalArgumentException
     */
    public void setServerName(String serverName) throws IllegalStateException, IllegalArgumentException {
        Assert.checkNotNullParam("serverName", serverName);
        stateRef.get().setServerName(serverName);
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
        Assert.checkNotNullParam("realmName", realmName);
        stateRef.get().setMechanismRealmName(realmName);
    }

    AtomicReference<State> getStateRef() {
        return stateRef;
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
                final AtomicReference<State> stateRef = getStateRef();
                final Callback callback = callbacks[idx];
                if (callback instanceof AnonymousAuthorizationCallback) {
                    ((AnonymousAuthorizationCallback) callback).setAuthorized(authorizeAnonymous());
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

                    try {
                        SecurityFactory<Credential> factory = stateRef.get().getMechanismConfiguration().getServerCredentialFactory();
                        if (factory != null) {
                            final Credential credential = factory.create();
                            if (serverCredentialCallback.isCredentialSupported(credential)) {
                                serverCredentialCallback.setCredential(credential);
                                handleOne(callbacks, idx + 1);
                                return;
                            }
                        }
                    } catch (GeneralSecurityException e) {
                        // skip this credential
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
                } else if (callback instanceof SSLSessionAuthorizationCallback) {
                    final SSLSessionAuthorizationCallback authorizationCallback = (SSLSessionAuthorizationCallback) callback;
                    final SSLSession sslSession = authorizationCallback.getSslSession();
                    final IdentityCache cache = (IdentityCache) SSLUtils.computeIfAbsent(sslSession, "org.wildfly.elytron.identity-cache", key -> new IdentityCache());
                    final SecurityDomain securityDomain = stateRef.get().getSecurityDomain();
                    final SecurityIdentity identity = cache.identities.get(securityDomain);
                    if (identity != null) {
                        authorizationCallback.setAuthorized(importIdentity(identity));
                    } else {
                        final X509Certificate[] x509Certificates;
                        try {
                            try {
                                x509Certificates = X500.asX509CertificateArray((Object[]) sslSession.getPeerCertificates());
                                final X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(x509Certificates);
                                final X500Principal principal = evidence.getPrincipal();
                                if (principal != null) {
                                    setAuthenticationPrincipal(principal);
                                    final boolean authorized = verifyEvidence(evidence) && authorize();
                                    authorizationCallback.setAuthorized(authorized);
                                    if (authorized) {
                                        // cache identity
                                        cache.identities.putIfAbsent(securityDomain, getAuthorizedIdentity());
                                    }
                                }
                            } catch (ArrayStoreException ignored) {
                                // unauthorized; fall out
                            }
                        } catch (SSLPeerUnverifiedException e) {
                            // unauthorized; fall out
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
                    Collection<String> names = stateRef.get().getMechanismConfiguration().getMechanismRealmNames();
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
                } else if (callback instanceof ServerNameCallback) {
                    ServerNameCallback snc = (ServerNameCallback) callback;
                    setServerName(snc.getServerName());
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

    NameAssignedState assignName(final SecurityIdentity capturedIdentity, final MechanismConfiguration mechanismConfiguration, final MechanismRealmConfiguration mechanismRealmConfiguration, String name, Principal originalPrincipal, final Evidence evidence) throws RealmUnavailableException {
        final SecurityDomain domain = capturedIdentity.getSecurityDomain();
        name = rewriteAll(name, mechanismRealmConfiguration.getPreRealmRewriter(), mechanismConfiguration.getPreRealmRewriter(), domain.getPreRealmRewriter());
        // principal *must* be captured at this point
        final NamePrincipal principal = new NamePrincipal(name);
        String realmName = mapAll(name, mechanismRealmConfiguration.getRealmMapper(), mechanismConfiguration.getRealmMapper(), domain.getRealmMapper(), domain.getDefaultRealmName());
        final RealmInfo realmInfo = domain.getRealmInfo(realmName);
        name = rewriteAll(name, mechanismRealmConfiguration.getPostRealmRewriter(), mechanismConfiguration.getPostRealmRewriter(), domain.getPostRealmRewriter());
        name = rewriteAll(name, mechanismRealmConfiguration.getFinalRewriter(), mechanismConfiguration.getFinalRewriter(), realmInfo.getNameRewriter());
        final SecurityRealm securityRealm = realmInfo.getSecurityRealm();
        final IdentityLocator.Builder locatorBuilder = IdentityLocator.builder();
        locatorBuilder.setName(name);
        locatorBuilder.setPrincipal(principal);
        locatorBuilder.setEvidence(evidence);
        final RealmIdentity realmIdentity = securityRealm.getRealmIdentity(locatorBuilder.build());
        return new NameAssignedState(capturedIdentity, realmInfo, realmIdentity, principal, mechanismConfiguration, mechanismRealmConfiguration);
    }

    abstract static class State {
        MechanismConfiguration getMechanismConfiguration() {
            throw log.noAuthenticationInProgress();
        }

        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            throw log.noAuthenticationInProgress();
        }

        SecurityIdentity getAuthorizedIdentity() {
            throw log.noAuthenticationInProgress();
        }

        Principal getAuthenticationPrincipal() {
            throw log.noAuthenticationInProgress();
        }

        boolean isSameName(String name) {
            return false;
        }

        boolean isSamePrincipal(Principal principal) {
            return false;
        }

        SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        boolean importIdentity(final SecurityIdentity identity) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        RealmIdentity getRealmIdentity() {
            throw log.noAuthenticationInProgress();
        }

        SecurityDomain getSecurityDomain() {
            throw log.noAuthenticationInProgress();
        }

        boolean authorizeAnonymous(final boolean requireLoginPermission) {
            throw log.noAuthenticationInProgress();
        }

        void setName(String name) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        void setPrincipal(Principal principal) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        boolean authorize(final boolean requireLoginPermission) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        boolean authorize(String authorizationId, final boolean authorizeRunAs) throws RealmUnavailableException {
            throw log.noAuthenticationInProgress();
        }

        void setMechanismRealmName(String name) {
            throw log.noAuthenticationInProgress();
        }

        void setServerName(String serverName) {
            throw log.noAuthenticationInProgress();
        }

        void succeed() {
            throw log.noAuthenticationInProgress();
        }

        void fail() {
            throw log.noAuthenticationInProgress();
        }

        boolean isDone() {
            return false;
        }
    }

    abstract class ActiveState extends State {

        ActiveState() {
        }

        boolean authorize(String authorizationId, boolean authorizeRunAs) throws RealmUnavailableException {
            final AtomicReference<State> stateRef = getStateRef();

            // get the identity we are authorizing from
            final SecurityIdentity sourceIdentity = getSourceIdentity();

            final NameAssignedState nameAssignedState = assignName(sourceIdentity, getMechanismConfiguration(), getMechanismRealmConfiguration(), authorizationId, null, null);
            final RealmIdentity realmIdentity = nameAssignedState.getRealmIdentity();
            boolean ok = false;
            try {
                if (! realmIdentity.exists()) {
                    return false;
                }
                // check the run-as permission on the old identity
                if (authorizeRunAs && ! sourceIdentity.implies(new RunAsPrincipalPermission(nameAssignedState.getAuthenticationPrincipal().getName()))) {
                    return false;
                }
                final AuthorizedAuthenticationState newState = nameAssignedState.doAuthorization(false);
                if (newState == null) {
                    return false;
                }
                if (! stateRef.compareAndSet(this, newState)) {
                    // try again
                    return stateRef.get().authorize(authorizationId, authorizeRunAs);
                }
                ok = true;
                return true;
            } finally {
                if (! ok) realmIdentity.dispose();
            }
        }

        @Override
        void setMechanismRealmName(final String realmName) {
            final MechanismRealmConfiguration currentConfiguration = getMechanismRealmConfiguration();
            final MechanismConfiguration mechanismConfiguration = getMechanismConfiguration();
            if (mechanismConfiguration.getMechanismRealmNames().isEmpty()) {
                // no realms are configured
                throw log.invalidMechRealmSelection(realmName);
            }
            final MechanismRealmConfiguration configuration = mechanismConfiguration.getMechanismRealmConfiguration(realmName);
            if (configuration == null) {
                throw log.invalidMechRealmSelection(realmName);
            }
            if (currentConfiguration != configuration) {
                throw log.mechRealmAlreadySelected();
            }
        }

        @Override
        void setServerName(String serverName) {
            final MechanismConfiguration currentConfiguration = getMechanismConfiguration();
            final MechanismConfiguration newConfiguration = currentConfiguration.forServer(serverName);
            if (currentConfiguration != newConfiguration) {
                throw log.serverNameAlreadySelected();
            }
        }

        abstract SecurityIdentity getSourceIdentity();
    }

    /**
     * State shared among both the initial state and the realm-assigned state, where no authentication name is yet set.
     */
    abstract class UnassignedState extends ActiveState {
        final SecurityIdentity capturedIdentity;
        final MechanismConfiguration mechanismConfiguration;

        UnassignedState(final SecurityIdentity capturedIdentity, final MechanismConfiguration mechanismConfiguration) {
            this.capturedIdentity = capturedIdentity;
            this.mechanismConfiguration = mechanismConfiguration;
        }

        SecurityIdentity getSourceIdentity() {
            return capturedIdentity;
        }

        @Override
        SecurityDomain getSecurityDomain() {
            return capturedIdentity.getSecurityDomain();
        }

        @Override
        void fail() {
            final AtomicReference<State> stateRef = getStateRef();
            if (! stateRef.compareAndSet(this, FAILED)) {
                // recurse & retry
                stateRef.get().fail();
            }
        }

        @Override
        boolean authorizeAnonymous(final boolean requireLoginPermission) {
            final AtomicReference<State> stateRef = getStateRef();
            final SecurityIdentity anonymousIdentity = getSecurityDomain().getAnonymousSecurityIdentity();
            return (! requireLoginPermission || anonymousIdentity.implies(LoginPermission.getInstance())) && (stateRef.compareAndSet(this, new AnonymousAuthorizedState(anonymousIdentity)) || stateRef.get().authorizeAnonymous(requireLoginPermission));
        }

        @Override
        boolean authorize(final boolean requireLoginPermission) throws RealmUnavailableException {
            final SecurityIdentity capturedIdentity = this.capturedIdentity;
            if (capturedIdentity.getPrincipal() instanceof AnonymousPrincipal) {
                return authorizeAnonymous(requireLoginPermission);
            }
            final AtomicReference<State> stateRef = getStateRef();
            return (! requireLoginPermission || capturedIdentity.implies(LoginPermission.getInstance())) && (stateRef.compareAndSet(this, new AuthorizedState(capturedIdentity, capturedIdentity.getPrincipal(), capturedIdentity.getRealmInfo(), mechanismConfiguration, getMechanismRealmConfiguration())) || stateRef.get().authorize(requireLoginPermission));
        }

        @Override
        boolean importIdentity(final SecurityIdentity importedIdentity) throws RealmUnavailableException {
            // As long as a name is not yet assigned, we can authorize an imported identity
            final RealmInfo evidenceRealmInfo = importedIdentity.getRealmInfo();
            final SecurityRealm evidenceSecurityRealm = evidenceRealmInfo.getSecurityRealm();
            final SecurityDomain evidenceSecurityDomain = importedIdentity.getSecurityDomain();
            final AtomicReference<State> stateRef = getStateRef();
            final SecurityIdentity sourceIdentity = getSourceIdentity();
            final SecurityDomain domain = sourceIdentity.getSecurityDomain();
            // Check that the given security identity evidence either corresponds to the same realm that created the
            // current authentication identity or it corresponds to a domain that is trusted by the current domain
            final Principal importedPrincipal = importedIdentity.getPrincipal();
            if (AnonymousPrincipal.getInstance().equals(importedPrincipal)) {
                AnonymousAuthorizedState newState = new AnonymousAuthorizedState(domain.getAnonymousSecurityIdentity());
                return stateRef.compareAndSet(this, newState) || stateRef.get().importIdentity(importedIdentity);
            }
            if (domain == importedIdentity.getSecurityDomain()) {
                // it's authorized already because it's the same domain
                AuthorizedState newState = new AuthorizedState(importedIdentity, importedPrincipal, importedIdentity.getRealmInfo(), mechanismConfiguration, getMechanismRealmConfiguration());
                return stateRef.compareAndSet(this, newState) || stateRef.get().importIdentity(importedIdentity);
            }

            boolean trusted = false;
            // it didn't come from our domain.  Check to see if it came from a trusted domain.
            if (domain.trustsDomain(evidenceSecurityDomain)) {
                trusted = true;
            }

            // Finally, run the identity through the normal name selection process.
            String name = domain.getPrincipalDecoder().getName(importedPrincipal);
            if (name == null) {
                throw log.unrecognizedPrincipalType(importedPrincipal);
            }
            final NameAssignedState nameState = assignName(sourceIdentity, mechanismConfiguration, getMechanismRealmConfiguration(), name, null, null);
            final RealmIdentity realmIdentity = nameState.getRealmIdentity();
            boolean ok = false;
            try {
                if (! trusted) {
                    if (nameState.getRealmInfo().getSecurityRealm() != evidenceSecurityRealm) {
                        // mapped realm does not correspond with the imported realm name
                        return false;
                    }
                }

                // with the name we have now, try and authorize
                final AuthorizedAuthenticationState authzState = nameState.doAuthorization(false);
                if (authzState == null) {
                    return false;
                }

                if (! stateRef.compareAndSet(this, authzState)) {
                    return stateRef.get().importIdentity(importedIdentity);
                }

                ok = true;
                return true;
            } finally {
                if (! ok) realmIdentity.dispose();
            }
        }

        @Override
        void setName(final String name) throws RealmUnavailableException {
            final AtomicReference<State> stateRef = getStateRef();
            final NameAssignedState newState = assignName(capturedIdentity, mechanismConfiguration, getMechanismRealmConfiguration(), name, null, null);
            if (! stateRef.compareAndSet(this, newState)) {
                newState.realmIdentity.dispose();
                stateRef.get().setName(name);
            }
        }

        @Override
        SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return getSecurityDomain().getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            // TODO: this method probably should never cause a state change... consider setEvidence or something instead?
            final AtomicReference<State> stateRef = getStateRef();
            final Principal evidencePrincipal = evidence.getPrincipal();
            final MechanismRealmConfiguration mechanismRealmConfiguration = getMechanismRealmConfiguration();
            if (evidencePrincipal != null) {
                String name = getSecurityDomain().getPrincipalDecoder().getName(evidencePrincipal);
                if (name != null) {
                    final NameAssignedState newState = assignName(getSourceIdentity(), mechanismConfiguration, mechanismRealmConfiguration, name, evidencePrincipal, evidence);
                    if (! newState.verifyEvidence(evidence)) {
                        newState.realmIdentity.dispose();
                        return false;
                    }
                    if (! stateRef.compareAndSet(this, newState)) {
                        newState.realmIdentity.dispose();
                        stateRef.get().setName(name);
                        return stateRef.get().verifyEvidence(evidence);
                    }
                    return true;
                }
            }
            // verify evidence with no name set: use the realms to find a match (SSO scenario, etc.)
            final SecurityDomain domain = getSecurityDomain();
            final Collection<RealmInfo> realmInfos = domain.getRealmInfos();
            RealmIdentity realmIdentity = null;
            RealmInfo realmInfo = null;
            final IdentityLocator locator = IdentityLocator.fromEvidence(evidence);
            for (RealmInfo info : realmInfos) {
                realmIdentity = info.getSecurityRealm().getRealmIdentity(locator);
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
            if (! realmIdentity.verifyEvidence(evidence)) {
                realmIdentity.dispose();
                return false;
            }
            final NameAssignedState newState = new NameAssignedState(getSourceIdentity(), realmInfo, realmIdentity, resolvedPrincipal, mechanismConfiguration, mechanismRealmConfiguration);
            if (! stateRef.compareAndSet(this, newState)) {
                realmIdentity.dispose();
                return stateRef.get().verifyEvidence(evidence);
            }
            return true;
        }

        @Override
        void setPrincipal(final Principal principal) throws RealmUnavailableException {
            Assert.checkNotNullParam("principal", principal);
            String name = getSecurityDomain().getPrincipalDecoder().getName(principal);
            if (name == null) {
                throw log.unrecognizedPrincipalType(principal);
            }
            final AtomicReference<State> stateRef = getStateRef();
            final NameAssignedState newState = assignName(capturedIdentity, mechanismConfiguration, getMechanismRealmConfiguration(), name, principal, null);
            if (! stateRef.compareAndSet(this, newState)) {
                newState.realmIdentity.dispose();
                stateRef.get().setName(name);
            }
        }

        @Override
        MechanismConfiguration getMechanismConfiguration() {
            return mechanismConfiguration;
        }
    }

    final class InitialState extends UnassignedState {

        InitialState(final SecurityIdentity capturedIdentity, final MechanismConfiguration mechanismConfiguration) {
            super(capturedIdentity, mechanismConfiguration);
        }

        @Override
        void setMechanismRealmName(final String realmName) {
            final MechanismConfiguration mechanismConfiguration = getMechanismConfiguration();
            if (mechanismConfiguration.getMechanismRealmNames().isEmpty()) {
                // no realms are configured
                throw log.invalidMechRealmSelection(realmName);
            }
            final MechanismRealmConfiguration configuration = mechanismConfiguration.getMechanismRealmConfiguration(realmName);
            if (configuration == null) {
                throw log.invalidMechRealmSelection(realmName);
            }
            final AtomicReference<State> stateRef = getStateRef();
            if (! stateRef.compareAndSet(this, new RealmAssignedState(capturedIdentity, mechanismConfiguration, configuration))) {
                stateRef.get().setMechanismRealmName(realmName);
            }
        }

        @Override
        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            final Collection<String> mechanismRealmNames = mechanismConfiguration.getMechanismRealmNames();
            final Iterator<String> iterator = mechanismRealmNames.iterator();
            if (iterator.hasNext()) {
                // use the default realm
                return mechanismConfiguration.getMechanismRealmConfiguration(iterator.next());
            } else {
                return MechanismRealmConfiguration.NO_REALM;
            }
        }

        @Override
        void setServerName(String serverName) {
            final MechanismConfiguration currentConfiguration = getMechanismConfiguration();
            final MechanismConfiguration newConfiguration = currentConfiguration.forServer(serverName);
            if (currentConfiguration != newConfiguration) {
                if (! stateRef.compareAndSet(this, new InitialState(capturedIdentity, newConfiguration))) {
                    stateRef.get().setServerName(serverName);
                }
            }
        }

    }

    final class RealmAssignedState extends UnassignedState {
        final MechanismRealmConfiguration mechanismRealmConfiguration;

        RealmAssignedState(final SecurityIdentity capturedIdentity, final MechanismConfiguration mechanismConfiguration, final MechanismRealmConfiguration mechanismRealmConfiguration) {
            super(capturedIdentity, mechanismConfiguration);
            this.mechanismRealmConfiguration = mechanismRealmConfiguration;
        }

        @Override
        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            return mechanismRealmConfiguration;
        }
    }

    final class NameAssignedState extends ActiveState {
        private final SecurityIdentity capturedIdentity;
        private final RealmInfo realmInfo;
        private final RealmIdentity realmIdentity;
        private final Principal authenticationPrincipal;
        private final MechanismConfiguration mechanismConfiguration;
        private final MechanismRealmConfiguration mechanismRealmConfiguration;

        NameAssignedState(final SecurityIdentity capturedIdentity, final RealmInfo realmInfo, final RealmIdentity realmIdentity, final Principal authenticationPrincipal, final MechanismConfiguration mechanismConfiguration, final MechanismRealmConfiguration mechanismRealmConfiguration) {
            this.capturedIdentity = capturedIdentity;
            this.realmInfo = realmInfo;
            this.realmIdentity = realmIdentity;
            this.authenticationPrincipal = authenticationPrincipal;
            this.mechanismConfiguration = mechanismConfiguration;
            this.mechanismRealmConfiguration = mechanismRealmConfiguration;
        }

        @Override
        MechanismConfiguration getMechanismConfiguration() {
            return mechanismConfiguration;
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
        RealmIdentity getRealmIdentity() {
            return realmIdentity;
        }

        @Override
        SecurityDomain getSecurityDomain() {
            return capturedIdentity.getSecurityDomain();
        }

        @Override
        SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getCredentialAcquireSupport(credentialType, algorithmName);
        }

        @Override
        SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getCredential(credentialType, algorithmName);
        }

        @Override
        boolean authorize(final boolean requireLoginPermission) throws RealmUnavailableException {
            AuthorizedAuthenticationState newState = doAuthorization(requireLoginPermission);
            if (newState == null) {
                return false;
            }
            final AtomicReference<State> stateRef = getStateRef();
            // retry if necessary
            return stateRef.compareAndSet(this, newState) || stateRef.get().authorize(requireLoginPermission);
        }

        AuthorizedAuthenticationState doAuthorization(final boolean requireLoginPermission) throws RealmUnavailableException {
            final RealmIdentity realmIdentity = this.realmIdentity;

            if (! realmIdentity.exists()) {
                return null;
            }

            final RealmInfo realmInfo = this.realmInfo;
            final Principal authenticationPrincipal = this.authenticationPrincipal;
            final AuthorizationIdentity authorizationIdentity = realmIdentity.getAuthorizationIdentity();
            final SecurityDomain domain = capturedIdentity.getSecurityDomain();

            final PeerIdentity[] peerIdentities = capturedIdentity.getPeerIdentities();

            final SecurityIdentity authorizedIdentity = Assert.assertNotNull(domain.transform(new SecurityIdentity(domain, authenticationPrincipal, realmInfo, authorizationIdentity, domain.getCategoryRoleMappers(), peerIdentities)));
            if (requireLoginPermission) {
                if (! authorizedIdentity.implies(LoginPermission.getInstance())) {
                    SecurityRealm.safeHandleRealmEvent(realmInfo.getSecurityRealm(), new RealmIdentityFailedAuthorizationEvent(authorizedIdentity.getAuthorizationIdentity(), authorizedIdentity.getPrincipal(), authenticationPrincipal));
                    return null;
                } else {
                    SecurityRealm.safeHandleRealmEvent(realmInfo.getSecurityRealm(), new RealmIdentitySuccessfulAuthorizationEvent(authorizedIdentity.getAuthorizationIdentity(), authorizedIdentity.getPrincipal(), authenticationPrincipal));
                }
            }
            return new AuthorizedAuthenticationState(authorizedIdentity, authenticationPrincipal, realmInfo, realmIdentity, mechanismRealmConfiguration, mechanismConfiguration);
        }

        @Override
        boolean authorize(final String authorizationId, final boolean authorizeRunAs) throws RealmUnavailableException {
            final AuthorizedAuthenticationState authzState = doAuthorization(true);
            if (authzState == null) {
                return false;
            }
            final AuthorizedState newState = authzState.authorizeRunAs(authorizationId, authorizeRunAs);
            if (newState == null) {
                return false;
            }
            final AtomicReference<State> stateRef = getStateRef();
            if (stateRef.compareAndSet(this, newState)) {
                getRealmIdentity().dispose();
                return true;
            } else {
                return stateRef.get().authorize(authorizationId, authorizeRunAs);
            }
        }

        @Override
        SecurityIdentity getSourceIdentity() {
            return capturedIdentity;
        }

        @Override
        boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            // At this stage, we just verify that the evidence principal matches, and verify it with the realm.
            final Principal evidencePrincipal = evidence.getPrincipal();
            return (evidencePrincipal == null || isSamePrincipal(evidencePrincipal)) && getRealmIdentity().verifyEvidence(evidence);
        }

        @Override
        void succeed() {
            throw log.cannotSucceedNotAuthorized();
        }

        @Override
        void fail() {
            final AtomicReference<State> stateRef = getStateRef();
            if (! stateRef.compareAndSet(this, FAILED)) {
                stateRef.get().fail();
                return;
            }
            realmIdentity.dispose();
        }

        @Override
        void setName(final String name) {
            if (isSameName(name)) {
                return;
            }
            throw log.nameAlreadySet();
        }

        @Override
        void setPrincipal(final Principal principal) {
            if (isSamePrincipal(principal)) {
                return;
            }
            throw log.nameAlreadySet();
        }

        @Override
        boolean isSameName(String name) {
            final SecurityDomain domain = capturedIdentity.getSecurityDomain();
            name = rewriteAll(name, mechanismRealmConfiguration.getPreRealmRewriter(), mechanismConfiguration.getPreRealmRewriter(), domain.getPreRealmRewriter());
            return authenticationPrincipal.equals(new NamePrincipal(name));
        }

        @Override
        boolean isSamePrincipal(final Principal principal) {
            String name = capturedIdentity.getSecurityDomain().getPrincipalDecoder().getName(principal);
            return isSameName(name);
        }

        RealmInfo getRealmInfo() {
            return realmInfo;
        }
    }

    final class AnonymousAuthorizedState extends ActiveState {
        private final SecurityIdentity anonymousIdentity;

        AnonymousAuthorizedState(final SecurityIdentity anonymousIdentity) {
            this.anonymousIdentity = anonymousIdentity;
        }

        @Override
        MechanismConfiguration getMechanismConfiguration() {
            return MechanismConfiguration.EMPTY;
        }

        @Override
        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            return MechanismRealmConfiguration.NO_REALM;
        }

        @Override
        SecurityIdentity getAuthorizedIdentity() {
            return anonymousIdentity;
        }

        @Override
        Principal getAuthenticationPrincipal() {
            return AnonymousPrincipal.getInstance();
        }

        @Override
        boolean isSameName(final String name) {
            return false;
        }

        @Override
        boolean isSamePrincipal(final Principal principal) {
            return principal instanceof AnonymousPrincipal;
        }

        @Override
        SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return null;
        }

        @Override
        boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            return false;
        }

        @Override
        RealmIdentity getRealmIdentity() {
            return RealmIdentity.ANONYMOUS;
        }

        @Override
        SecurityDomain getSecurityDomain() {
            return anonymousIdentity.getSecurityDomain();
        }

        @Override
        boolean authorizeAnonymous(final boolean requireLoginPermission) {
            return true;
        }

        @Override
        void setName(final String name) throws RealmUnavailableException {
            // reject all names
            super.setName(name);
        }

        @Override
        void setPrincipal(final Principal principal) throws RealmUnavailableException {
            if (! (principal instanceof AnonymousPrincipal)) {
                super.setPrincipal(principal);
            }
        }

        @Override
        boolean authorize(final boolean requireLoginPermission) throws RealmUnavailableException {
            return ! requireLoginPermission || anonymousIdentity.implies(LoginPermission.getInstance());
        }

        @Override
        void succeed() {
            final AtomicReference<State> stateRef = getStateRef();
            if (! stateRef.compareAndSet(this, new CompleteState(anonymousIdentity))) {
                stateRef.get().succeed();
            }
        }

        @Override
        void fail() {
            final AtomicReference<State> stateRef = getStateRef();
            if (! stateRef.compareAndSet(this, FAILED)) {
                stateRef.get().fail();
            }
        }

        @Override
        SecurityIdentity getSourceIdentity() {
            return anonymousIdentity;
        }
    }

    class AuthorizedState extends ActiveState {
        private final SecurityIdentity authorizedIdentity;
        private final Principal authenticationPrincipal;
        private final RealmInfo realmInfo;
        private final MechanismConfiguration mechanismConfiguration;
        private final MechanismRealmConfiguration mechanismRealmConfiguration;

        AuthorizedState(final SecurityIdentity authorizedIdentity, final Principal authenticationPrincipal, final RealmInfo realmInfo, final MechanismConfiguration mechanismConfiguration, final MechanismRealmConfiguration mechanismRealmConfiguration) {
            this.authorizedIdentity = authorizedIdentity;
            this.authenticationPrincipal = authenticationPrincipal;
            this.realmInfo = realmInfo;
            this.mechanismConfiguration = mechanismConfiguration;
            this.mechanismRealmConfiguration = mechanismRealmConfiguration;
        }

        @Override
        MechanismRealmConfiguration getMechanismRealmConfiguration() {
            return mechanismRealmConfiguration;
        }

        @Override
        MechanismConfiguration getMechanismConfiguration() {
            return mechanismConfiguration;
        }

        @Override
        SecurityIdentity getAuthorizedIdentity() {
            return authorizedIdentity;
        }

        @Override
        Principal getAuthenticationPrincipal() {
            return authenticationPrincipal;
        }

        @Override
        SecurityDomain getSecurityDomain() {
            return authorizedIdentity.getSecurityDomain();
        }

        @Override
        SecurityIdentity getSourceIdentity() {
            return authorizedIdentity;
        }

        RealmInfo getRealmInfo() {
            return realmInfo;
        }

        boolean authorize(final boolean requireLoginPermission) throws RealmUnavailableException {
            return ! requireLoginPermission || authorizedIdentity.implies(LoginPermission.getInstance());
        }

        AuthorizedState authorizeRunAs(final String authorizationId, final boolean authorizeRunAs) throws RealmUnavailableException {
            final NameAssignedState nameAssignedState = assignName(authorizedIdentity, getMechanismConfiguration(), getMechanismRealmConfiguration(), authorizationId, null, null);
            final RealmIdentity realmIdentity = nameAssignedState.getRealmIdentity();
            boolean ok = false;
            try {
                if (authorizationId.equals(authenticationPrincipal.getName())) {
                    // same identity; clean up & return
                    return this;
                }
                if (authorizeRunAs && ! authorizedIdentity.implies(new RunAsPrincipalPermission(nameAssignedState.getAuthenticationPrincipal().getName()))) {
                    // not authorized; clean up & return
                    return null;
                }
                final AuthorizedAuthenticationState newState = nameAssignedState.doAuthorization(false);
                if (newState == null) {
                    // not authorized; clean up & return
                    return null;
                }
                ok = true;
                return newState;
            } finally {
                if (! ok) realmIdentity.dispose();
            }
        }
    }

    final class AuthorizedAuthenticationState extends AuthorizedState {
        private final RealmIdentity realmIdentity;

        AuthorizedAuthenticationState(final SecurityIdentity authorizedIdentity, final Principal authenticationPrincipal, final RealmInfo realmInfo, final RealmIdentity realmIdentity, final MechanismRealmConfiguration mechanismRealmConfiguration, final MechanismConfiguration mechanismConfiguration) {
            super(authorizedIdentity, authenticationPrincipal, realmInfo, mechanismConfiguration, mechanismRealmConfiguration);
            this.realmIdentity = realmIdentity;
        }

        @Override
        SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getCredentialAcquireSupport(credentialType, algorithmName);
        }

        @Override
        SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        <C extends Credential> C getCredential(final Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
            return realmIdentity.getCredential(credentialType, algorithmName);
        }

        @Override
        boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            return realmIdentity.verifyEvidence(evidence);
        }

        @Override
        RealmIdentity getRealmIdentity() {
            return realmIdentity;
        }

        @Override
        void succeed() {
            final SecurityIdentity authorizedIdentity = getSourceIdentity();
            final AtomicReference<State> stateRef = getStateRef();
            if (stateRef.compareAndSet(this, new CompleteState(authorizedIdentity))) {
                SecurityRealm.safeHandleRealmEvent(getRealmInfo().getSecurityRealm(), new RealmSuccessfulAuthenticationEvent(realmIdentity, authorizedIdentity.getAuthorizationIdentity(), null, null));
                realmIdentity.dispose();
                return;
            }
            stateRef.get().succeed();
        }

        @Override
        void fail() {
            final AtomicReference<State> stateRef = getStateRef();
            if (stateRef.compareAndSet(this, FAILED)) {
                SecurityRealm.safeHandleRealmEvent(getRealmInfo().getSecurityRealm(), new RealmFailedAuthenticationEvent(realmIdentity, null, null));
                realmIdentity.dispose();
                return;
            }
            stateRef.get().fail();
        }
    }

    static final class CompleteState extends State {
        private final SecurityIdentity identity;

        public CompleteState(final SecurityIdentity identity) {
            this.identity = identity;
        }

        @Override
        SecurityIdentity getAuthorizedIdentity() {
            return identity;
        }

        @Override
        boolean isDone() {
            return true;
        }

        void succeed() {
            // always works
        }
    }

    private static final State FAILED = new State() {
        @Override
        void fail() {
        }

        @Override
        boolean isDone() {
            return true;
        }
    };

    static class IdentityCache {
        final ConcurrentHashMap<SecurityDomain, SecurityIdentity> identities = new ConcurrentHashMap<>();
    }
}
