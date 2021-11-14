/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.sfbasic;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.fill;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.common.array.Arrays2.indexOf;
import static org.wildfly.security.http.HttpConstants.AUTHORIZATION;
import static org.wildfly.security.http.HttpConstants.CHARSET;
import static org.wildfly.security.http.HttpConstants.HOST;
import static org.wildfly.security.http.HttpConstants.REALM;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;
import static org.wildfly.security.http.sfbasic.BasicMechanismFactory.COOKIE_NAME;
import static org.wildfly.security.http.sfbasic.BasicMechanismFactory.STATEFUL_BASIC_NAME;
import static org.wildfly.security.mechanism._private.ElytronMessages.httpBasic;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.mechanism.http.UsernamePasswordAuthenticationMechanism;

/**
 * Implementation of the HTTP BASIC authentication mechanism
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class BasicAuthenticationMechanism extends UsernamePasswordAuthenticationMechanism {

    static final String SILENT = "silent";

    private static final String CHALLENGE_PREFIX = "Basic ";
    private static final int PREFIX_LENGTH = CHALLENGE_PREFIX.length();

    private final IdentityManager identityManager;

    private final boolean includeCharset;
    private final String configuredRealm;

    /**
     * If silent is true then this mechanism will only take effect if there is an Authorization header.
     *
     * This allows you to combine basic auth with form auth, so human users will use form based auth, but allows
     * programmatic clients to login using basic auth.
     */
    private final boolean silent;

    /**
     * Construct a new instance of {@code BasicAuthenticationMechanism}.
     *
     * @param callbackHandler the {@link CallbackHandler} to use to verify the supplied credentials and to notify to establish the current identity.
     * @param configuredRealm a configured realm name from the configuration.
     * @param includeCharset should the charset be included in the challenge.
     */
    BasicAuthenticationMechanism(final CallbackHandler callbackHandler, final IdentityManager identityManager,
                                 final String configuredRealm, final boolean silent, final boolean includeCharset) {
        super(checkNotNullParam("callbackHandler", callbackHandler));

        this.identityManager = identityManager;
        this.includeCharset = includeCharset;
        this.configuredRealm = configuredRealm;
        this.silent = silent;
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#getMechanismName()
     */
    @Override
    public String getMechanismName() {
        return STATEFUL_BASIC_NAME;
    }

    /**
     * @throws HttpAuthenticationException
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanism#evaluateRequest(HttpServerRequest)
     */
    @Override
    public void evaluateRequest(final HttpServerRequest request) throws HttpAuthenticationException {
        final String displayRealmName;
        String mechanismRealm = null;

        String[] realms = null;
        final AvailableRealmsCallback availableRealmsCallback = new AvailableRealmsCallback();
        try {
            callbackHandler.handle(new Callback[] { availableRealmsCallback });
            realms = availableRealmsCallback.getRealmNames();
        } catch (UnsupportedCallbackException ignored) {
        } catch (HttpAuthenticationException e) {
            throw e;
        } catch (IOException e) {
            throw httpBasic.mechCallbackHandlerFailedForUnknownReason(e).toHttpAuthenticationException();
        }

        if (configuredRealm != null) {
            displayRealmName = configuredRealm;
        } else if (realms != null && realms.length > 0) {
            displayRealmName = realms[0];
            mechanismRealm = displayRealmName;
        } else {
            displayRealmName = request.getFirstRequestHeaderValue(HOST);
        }

        if (mechanismRealm == null && realms != null && realms.length > 0) {
            for (String current : realms) {
                if (displayRealmName.equals(current)) {
                    mechanismRealm = displayRealmName;
                }
            }
            if (mechanismRealm == null) {
                mechanismRealm = realms[0];
            }
        }

        if (attemptReAuthentication(request)) {
            return;
        }

        List<String> authorizationValues = request.getRequestHeaderValues(AUTHORIZATION);
        if (authorizationValues != null) {
            for (String current : authorizationValues) {
                if (current.startsWith(CHALLENGE_PREFIX)) {
                    byte[] decodedValue = ByteIterator.ofBytes(current.substring(PREFIX_LENGTH).getBytes(UTF_8)).asUtf8String().base64Decode().drain();

                    // Note: A ':' can not be present in the username but it can be present in the password so the first ':' is the delimiter.
                    int colonPos = indexOf(decodedValue, ':');
                    if (colonPos <= 0) {
                        // We flag as failed so the browser is re-challenged - sending an error the browser believes it's input was valid.
                        request.authenticationFailed(httpBasic.incorrectlyFormattedHeader(AUTHORIZATION), response -> prepareResponse(request, displayRealmName, response));
                        return;
                    }

                    ByteBuffer usernameBytes = ByteBuffer.wrap(decodedValue, 0, colonPos);
                    ByteBuffer passwordBytes = ByteBuffer.wrap(decodedValue, colonPos + 1, decodedValue.length - colonPos - 1);

                    CharBuffer usernameChars = UTF_8.decode(usernameBytes);
                    CharBuffer passwordChars = UTF_8.decode(passwordBytes);

                    char[] password = new char[passwordChars.length()];
                    passwordChars.get(password);
                    try {
                        String username = usernameChars.toString();

                        if (authenticate(mechanismRealm, username, password)) {
                            httpBasic.tracef("User %s authenticated successfully!", username);

                            BasicIdentityCache identityCache = new BasicIdentityCache();

                            if (authorize(username, identityCache)) {
                                httpBasic.debugf("User %s authorization succeeded!", username);
                                succeed();

                                request.authenticationComplete(identityCache, identityCache::remove);
                                return;
                            } else {
                                httpBasic.debugf("User %s authorization failed.", username);
                                fail();

                                request.authenticationFailed(httpBasic.authorizationFailed(username), response -> prepareResponse(request, displayRealmName, response));
                                return;
                            }

                        } else {
                            httpBasic.debugf("User %s authentication failed.", username);
                            fail();

                            request.authenticationFailed(httpBasic.authenticationFailed(username, STATEFUL_BASIC_NAME), response -> prepareResponse(request, displayRealmName, response));
                            return;
                        }
                    } catch (IOException | UnsupportedCallbackException e) {
                        throw new HttpAuthenticationException(e);
                    } finally {
                        fill(password, (char) 0x00);
                        if (passwordChars.hasArray()) {
                            fill(passwordChars.array(), (char) 0x00);
                        }
                    }
                }
            }
        }

        request.noAuthenticationInProgress(response -> prepareResponse(request, displayRealmName, response));
    }

    private boolean attemptReAuthentication(final HttpServerRequest request) throws HttpAuthenticationException {
        String sessionID = null;
        for (HttpServerCookie cookie : request.getCookies()) {
           if (COOKIE_NAME.equals(cookie.getName())) {
               sessionID = cookie.getValue();
               break;
           }
        }

        if (sessionID != null) {
            BasicIdentityCache identityCache = new BasicIdentityCache(sessionID);
            CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(identityCache);
            try {
                callbackHandler.handle(new Callback[]{authorizeCallback});
            } catch (IOException | UnsupportedCallbackException e) {
                throw new HttpAuthenticationException(e);
            }
            if (authorizeCallback.isAuthorized()) {
                try {
                    succeed();
                } catch (IOException | UnsupportedCallbackException e) {
                    throw new HttpAuthenticationException(e);
                }
                httpBasic.tracef("Authorized existing session '%s'.", sessionID);
                // We need the cookie to be sent after re-authentication to extend the validity.
                request.authenticationComplete(identityCache, identityCache::remove);
                request.resumeRequest();
                return true;
            } else {
                httpBasic.tracef("Unable to authorize session '%s'", sessionID);
            }
        } else {
            httpBasic.trace("No authentication session cookie found.");
        }

        return false;
    }

    private boolean authorize(String username, IdentityCache identityCache)
            throws HttpAuthenticationException {
        CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(username, identityCache);
        try {
            callbackHandler.handle(new Callback[] { authorizeCallback });
            return authorizeCallback.isAuthorized();
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }
    }

    private void prepareResponse(final HttpServerRequest request, String realmName, HttpServerResponse response) {
        if (silent) {
            //if silent we only send a challenge if the request contained auth headers
            //otherwise we assume another method will send the challenge
            String authHeader = request.getFirstRequestHeaderValue(AUTHORIZATION);
            if(authHeader == null) {
                httpBasic.tracef("BASIC authentication mechanism ignored - " +
                        "configuration is set to silent and request does not contain Authorization header");
                return;     //CHALLENGE NOT SENT
            }
        }
        StringBuilder sb = new StringBuilder(CHALLENGE_PREFIX);
        sb.append(REALM).append("=\"").append(realmName).append("\"");
        if (includeCharset) {
            sb.append(", ").append(CHARSET).append("=\"UTF-8\"");
        }
        response.addResponseHeader(WWW_AUTHENTICATE, sb.toString());
        response.setStatusCode(UNAUTHORIZED);
    }

    private final class BasicIdentityCache implements IdentityCache, HttpServerMechanismsResponder {

        private String sessionID;

        BasicIdentityCache() {
        }

        BasicIdentityCache(final String sessionID) {
            this.sessionID = sessionID;
        }

        @Override
        public void sendResponse(HttpServerResponse response) throws HttpAuthenticationException {
            if (sessionID != null) {
                httpBasic.tracef("Sending session cookie for '%s'", sessionID);
                response.setResponseCookie(createCookie(COOKIE_NAME, sessionID));
            }
        }

        @Override
        public void put(SecurityIdentity identity) {
            CachedIdentity cachedIdentity = new CachedIdentity(CHALLENGE_PREFIX, false, identity);

            sessionID = identityManager.storeIdentity(sessionID, cachedIdentity);
        }

        @Override
        public CachedIdentity get() {
            if (sessionID != null) {
                return identityManager.retrieveIdentity(sessionID);
            }
            return null;
        }

        @Override
        public CachedIdentity remove() {
            if (sessionID != null) {
                return identityManager.removeIdentity(sessionID);
            }

            return null;
        }

    }

    private static HttpServerCookie createCookie(final String name, final String value) {
        return new HttpServerCookie() {

            @Override
            public boolean isSecure() {
                return false;
            }

            @Override
            public boolean isHttpOnly() {
                return false;
            }

            @Override
            public int getVersion() {
                return 0;
            }

            @Override
            public String getValue() {
                return value;
            }

            @Override
            public String getPath() {
                return "/";
            }

            @Override
            public String getName() {
                return name;
            }

            @Override
            public int getMaxAge() {
                return -1;
            }

            @Override
            public String getDomain() {
                return null;
            }
        };
    }

}
