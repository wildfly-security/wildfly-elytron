/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.impl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.AUTHORIZATION;
import static org.wildfly.security.http.HttpConstants.CONFIG_GSS_MANAGER;
import static org.wildfly.security.http.HttpConstants.FORBIDDEN;
import static org.wildfly.security.http.HttpConstants.NEGOTIATE;
import static org.wildfly.security.http.HttpConstants.SPNEGO_NAME;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;
import static org.wildfly.security.http.HttpConstants.CONFIG_STATE_SCOPES;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BooleanSupplier;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.sasl.AuthorizeCallback;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.callback.ServerCredentialCallback;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.credential.GSSKerberosCredential;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.Scope;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.MechanismUtil;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util._private.Arrays2;

/**
 * A {@link HttpServerAuthenticationMechanism} implementation to support SPNEGO.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SpnegoAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private static final String CHALLENGE_PREFIX = NEGOTIATE + " ";

    private static final String GSS_CONTEXT_KEY = SpnegoAuthenticationMechanism.class.getName() + ".GSSContext";
    private static final String KERBEROS_TICKET = SpnegoAuthenticationMechanism.class.getName() + ".KerberosTicket";
    private static final String CACHED_IDENTITY_KEY = SpnegoAuthenticationMechanism.class.getName() + ".elytron-identity";

    private final CallbackHandler callbackHandler;
    private final GSSManager gssManager;
    private final Scope[] storageScopes;

    SpnegoAuthenticationMechanism(final CallbackHandler callbackHandler, final Map<String, ?> properties) {
        checkNotNullParam("callbackHandler", callbackHandler);
        checkNotNullParam("properties", properties);

        this.callbackHandler = callbackHandler;
        this.gssManager = properties.containsKey(CONFIG_GSS_MANAGER) ? (GSSManager) properties.get(CONFIG_GSS_MANAGER) : GSSManager.getInstance();

        String scopesProperty = (String) properties.get(CONFIG_STATE_SCOPES);
        if (scopesProperty == null) {
            storageScopes = new Scope[] { Scope.SESSION, Scope.CONNECTION };
        } else {
            String[] names = scopesProperty.split(",");
            storageScopes = new Scope[names.length];
            for (int i=0;i<names.length;i++) {
                if ("NONE".equals(names[i])) {
                    storageScopes[i] = null;
                } else {
                    Scope scope = Scope.valueOf(names[i]);
                    if (scope == Scope.APPLICATION || scope == Scope.GLOBAL) {
                        throw log.unsuitableScope(scope.name());
                    }
                    storageScopes[i] = scope;
                }
            }
        }
    }

    @Override
    public String getMechanismName() {
        return SPNEGO_NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        HttpScope storageScope = getStorageScope(request);
        IdentityCache identityCache = null;

        identityCache = createIdentityCache(identityCache, storageScope, false);
        if (identityCache != null && attemptReAuthentication(identityCache, request)) {
            log.trace("Successfully authorized using cached identity");
            return;
        }

        // If the scope does not already exist it can't have previously been used to store state.
        boolean scopeIsUsable = storageScope != null && storageScope.exists();
        GSSContext gssContext = scopeIsUsable ? storageScope.getAttachment(GSS_CONTEXT_KEY, GSSContext.class) : null;
        KerberosTicket kerberosTicket = scopeIsUsable ? storageScope.getAttachment(KERBEROS_TICKET, KerberosTicket.class) : null;
        log.tracef("Evaluating SPNEGO request: cached GSSContext = %s", gssContext);

        // Do we already have a cached identity? If so use it.
        if (gssContext != null && gssContext.isEstablished()) {
            identityCache = createIdentityCache(identityCache, storageScope, true);

            if (authorizeSrcName(gssContext, identityCache)) {
                log.trace("Successfully authorized using cached GSSContext");
                request.authenticationComplete();
                return;
            } else {
                clearAttachments(storageScope);
                gssContext = null;
                kerberosTicket = null;
            }
        }

        if (gssContext == null) { // init GSSContext
            ServerCredentialCallback gssCredentialCallback = new ServerCredentialCallback(GSSKerberosCredential.class);
            final GSSCredential serviceGssCredential;

            try {
                log.trace("Obtaining GSSCredential for the service from callback handler...");
                callbackHandler.handle(new Callback[] { gssCredentialCallback });
                serviceGssCredential = gssCredentialCallback.applyToCredential(GSSKerberosCredential.class, GSSKerberosCredential::getGssCredential);
                kerberosTicket = gssCredentialCallback.applyToCredential(GSSKerberosCredential.class, GSSKerberosCredential::getKerberosTicket);
            } catch (IOException | UnsupportedCallbackException e) {
                throw log.mechCallbackHandlerFailedForUnknownReason(SPNEGO_NAME, e).toHttpAuthenticationException();
            }

            if (serviceGssCredential == null) {
                throw log.unableToObtainServerCredential(SPNEGO_NAME).toHttpAuthenticationException();
            }

            try {
                gssContext = gssManager.createContext(serviceGssCredential);

                if (log.isTraceEnabled()) {
                    log.tracef("Using SpnegoAuthenticationMechanism to authenticate %s using the following mechanisms: [%s]",
                            serviceGssCredential.getName(), Arrays2.objectToString(serviceGssCredential.getMechs()));
                }
            } catch (GSSException e) {
                throw log.mechUnableToCreateGssContext(SPNEGO_NAME, e).toHttpAuthenticationException();
            }
        }

        // authentication exchange
        List<String> authorizationValues = request.getRequestHeaderValues(AUTHORIZATION);
        Optional<String> challenge = authorizationValues != null ? authorizationValues.stream()
                .filter(s -> s.startsWith(CHALLENGE_PREFIX)).limit(1).map(s -> s.substring(CHALLENGE_PREFIX.length()))
                .findFirst() : Optional.empty();

        if (log.isTraceEnabled()) {
            log.tracef("Sent HTTP authorizations: [%s]", Arrays2.objectToString(authorizationValues));
        }

        // Do we have an incoming response to a challenge? If so, process it.
        if (challenge.isPresent()) {
            log.trace("Processing incoming response to a challenge...");

            // We only need to store the scope if we have a challenge otherwise the next round
            // trip will be a new response anyway.
            if (storageScope != null && (storageScope.exists() || storageScope.create())) {
                storageScope.setAttachment(GSS_CONTEXT_KEY, gssContext);
                log.tracef("Caching GSSContext %s", gssContext);
                storageScope.setAttachment(KERBEROS_TICKET, kerberosTicket);
                log.tracef("Caching KerberosTicket %s", kerberosTicket);
            } else {
                storageScope = null;
                log.trace("No usable HttpScope for storage, continuation will not be possible");
            }

            byte[] decodedValue = ByteIterator.ofBytes(challenge.get().getBytes(UTF_8)).base64Decode().drain();

            Subject subject = new Subject(true, Collections.emptySet(), Collections.emptySet(), kerberosTicket != null ? Collections.singleton(kerberosTicket) : Collections.emptySet());

            byte[] responseToken;
            try {
                final GSSContext finalGssContext = gssContext;
                responseToken = Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () -> finalGssContext.acceptSecContext(decodedValue, 0, decodedValue.length));
            } catch (PrivilegedActionException e) {
                log.trace("Call to acceptSecContext failed.", e.getCause());
                handleCallback(AuthenticationCompleteCallback.FAILED);
                clearAttachments(storageScope);
                request.authenticationFailed(log.authenticationFailed(SPNEGO_NAME));
                return;
            }

            if (gssContext.isEstablished()) {
                final GSSCredential gssCredential;

                try {
                    gssCredential = gssContext.getCredDelegState() ? gssContext.getDelegCred() : null;
                } catch (GSSException e) {
                    log.trace("Unable to access delegated credential despite being delegated.", e);
                    handleCallback(AuthenticationCompleteCallback.FAILED);
                    clearAttachments(storageScope);
                    request.authenticationFailed(log.authenticationFailed(SPNEGO_NAME));
                    return;
                }

                if (gssCredential != null) {
                    log.trace("Associating delegated GSSCredential with identity.");
                    handleCallback(new IdentityCredentialCallback(new GSSKerberosCredential(gssCredential), true));
                } else {
                    log.trace("No GSSCredential delegated from client.");
                }

                log.trace("GSSContext established, authorizing...");

                identityCache = createIdentityCache(identityCache, storageScope, true);
                if (authorizeSrcName(gssContext, identityCache)) {
                    log.trace("GSSContext established and authorized - authentication complete");
                    request.authenticationComplete(response -> sendChallenge(responseToken, response, 0));

                    return;
                } else {
                    log.trace("Authorization of established GSSContext failed");
                    handleCallback(AuthenticationCompleteCallback.FAILED);
                    clearAttachments(storageScope);
                    request.authenticationFailed(log.authenticationFailed(SPNEGO_NAME), response -> sendChallenge(responseToken, response, FORBIDDEN));
                    return;
                }
            } else if (responseToken != null && storageScope != null) {
                log.trace("GSSContext establishing - sending negotiation token to the peer");
                request.authenticationInProgress(response -> sendChallenge(responseToken, response, UNAUTHORIZED));
                return;
            } else {
                log.trace("GSSContext establishing - unable to hold GSSContext so continuation will not be possible");
                handleCallback(AuthenticationCompleteCallback.FAILED);
                request.authenticationFailed(log.authenticationFailed(SPNEGO_NAME));
                return;
            }
        }

        log.trace("Request lacks valid authentication credentials");
        clearAttachments(storageScope);
        request.noAuthenticationInProgress(this::sendBareChallenge);
    }

    private HttpScope getStorageScope(HttpServerRequest request) throws HttpAuthenticationException {
        for (Scope scope : storageScopes) {
            if (scope == null) {
                return null;
            }
            HttpScope httpScope = request.getScope(scope);
            if (httpScope != null && httpScope.supportsAttachments()) {
                if (log.isTraceEnabled()) {
                    log.tracef("Using HttpScope '%s' with ID '%s'", scope.name(), httpScope.getID());
                }
                return httpScope;
            } else {
                if (log.isTraceEnabled()) {
                    log.tracef(httpScope == null ? "HttpScope %s not supported" : "HttpScope %s does not support attachments", scope);
                }
            }
        }

        throw log.unableToIdentifyHttpScope();
    }

    private IdentityCache createIdentityCache(final IdentityCache existingCache, final HttpScope httpScope, boolean forUpdate) {
        if (existingCache != null || // If we have a cache continue to use it.
                httpScope == null || // If we don't have a scope we can't create a cache (existing cache is null so return it)
                !httpScope.supportsAttachments() || // It is not null but if it doesn't support attachments pointless to wrap in a cache
                (!httpScope.exists() && (!forUpdate || !httpScope.create())) // Doesn't exist and if update is requested can't be created
                ) {
            return existingCache;
        }

        return new IdentityCache() {

            @Override
            public CachedIdentity remove() {
                CachedIdentity cachedIdentity = get();

                httpScope.setAttachment(CACHED_IDENTITY_KEY, null);

                return cachedIdentity;
            }

            @Override
            public void put(SecurityIdentity identity) {
                httpScope.setAttachment(CACHED_IDENTITY_KEY, new CachedIdentity(SPNEGO_NAME, identity));
            }

            @Override
            public CachedIdentity get() {
                return httpScope.getAttachment(CACHED_IDENTITY_KEY, CachedIdentity.class);
            }
        };

    }

    private static void clearAttachments(HttpScope scope) {
        if (scope != null) {
            scope.setAttachment(GSS_CONTEXT_KEY, null); // clear cache
            scope.setAttachment(KERBEROS_TICKET, null); // clear cache
        }
    }

    private void sendBareChallenge(HttpServerResponse response) {
        response.addResponseHeader(WWW_AUTHENTICATE, NEGOTIATE);
        response.setStatusCode(UNAUTHORIZED);
    }

    private void sendChallenge(byte[] responseToken, HttpServerResponse response, int statusCode) {
        if (log.isTraceEnabled()) {
            log.tracef("Sending intermediate challenge: %s", Arrays2.objectToString(responseToken));
        }
        if (responseToken == null) {
            response.addResponseHeader(WWW_AUTHENTICATE, NEGOTIATE);
        } else {
            String responseConverted = ByteIterator.ofBytes(responseToken).base64Encode().drainToString();
            response.addResponseHeader(WWW_AUTHENTICATE, CHALLENGE_PREFIX + responseConverted);
        }
        if (statusCode != 0) {
            response.setStatusCode(statusCode);
        }
    }

    private boolean attemptReAuthentication(IdentityCache identityCache, HttpServerRequest request) throws HttpAuthenticationException {
        CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(identityCache);
        try {
            callbackHandler.handle(new Callback[] { authorizeCallback });
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }
        if (authorizeCallback.isAuthorized()) {
            try {
                handleCallback(AuthenticationCompleteCallback.SUCCEEDED);
            } catch (IOException e) {
                throw new HttpAuthenticationException(e);
            }
            request.authenticationComplete(null, identityCache::remove);
            return true;
        }

        return false;
    }

    private boolean authorizeSrcName(GSSContext gssContext, IdentityCache identityCache) throws HttpAuthenticationException {
        final GSSName srcName;
        try {
            srcName = gssContext.getSrcName();
            if (srcName == null) {
                log.trace("Authorization failed - srcName of GSSContext (name of initiator) is null - wrong realm or kdc?");
                return false;
            }
        } catch (GSSException e) {
            log.trace("Unable to obtain srcName from established GSSContext.", e);
            return false;
        }

        final BooleanSupplier authorizedFunction;
        final Callback authorizeCallBack;

        if (gssContext.getCredDelegState()) {
            try {
                GSSCredential credential = gssContext.getDelegCred();
                log.tracef("Credential delegation enabled, delegated credential = %s", credential);
                MechanismUtil.handleCallbacks(SPNEGO_NAME, callbackHandler, new IdentityCredentialCallback(new GSSKerberosCredential(credential), true));
            } catch (UnsupportedCallbackException ignored) {
                // ignored
            } catch (AuthenticationMechanismException e) {
                throw e.toHttpAuthenticationException();
            } catch (GSSException e) {
                throw new HttpAuthenticationException(e);
            }
        } else {
            log.trace("Credential delegation not enabled");
        }

        boolean authorized = false;
        try {
            String clientName = srcName.toString();

            if (identityCache != null) {
                CachedIdentityAuthorizeCallback cacheCallback = new CachedIdentityAuthorizeCallback(new NamePrincipal(clientName), identityCache, true);
                authorizedFunction = cacheCallback::isAuthorized;
                authorizeCallBack = cacheCallback;
            } else {
                AuthorizeCallback plainCallback = new AuthorizeCallback(clientName, clientName);
                authorizedFunction = plainCallback::isAuthorized;
                authorizeCallBack = plainCallback;
            }
            callbackHandler.handle(new Callback[] { authorizeCallBack });
            authorized = authorizedFunction.getAsBoolean();
            log.tracef("Authorized by callback handler = %b  clientName = [%s]", authorized, clientName);
        } catch (IOException e) {
            log.trace("IOException during AuthorizeCallback handling", e);
            throw log.mechServerSideAuthenticationFailed(SPNEGO_NAME, e).toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
        }

        if (authorized) {
            // If we fail the caller may still decide to try and continue authentication.
            handleCallback(AuthenticationCompleteCallback.SUCCEEDED);
        }
        return authorized;
    }

    private void handleCallback(Callback callback) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(SPNEGO_NAME, callbackHandler, callback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
        }
    }

}
