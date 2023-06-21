/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.ACCEPT;
import static org.wildfly.security.http.oidc.Oidc.AuthOutcome;
import static org.wildfly.security.http.oidc.Oidc.FACES_REQUEST;
import static org.wildfly.security.http.oidc.Oidc.HTML_CONTENT_TYPE;
import static org.wildfly.security.http.oidc.Oidc.PARTIAL;
import static org.wildfly.security.http.oidc.Oidc.SOAP_ACTION;
import static org.wildfly.security.http.oidc.Oidc.TEXT_CONTENT_TYPE;
import static org.wildfly.security.http.oidc.Oidc.WILDCARD_CONTENT_TYPE;
import static org.wildfly.security.http.oidc.Oidc.XML_HTTP_REQUEST;
import static org.wildfly.security.http.oidc.Oidc.X_REQUESTED_WITH;

import java.util.Collections;
import java.util.List;

import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.Scope;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class RequestAuthenticator {

    protected OidcHttpFacade facade;
    protected AuthChallenge challenge;
    protected OidcClientConfiguration deployment;
    protected int sslRedirectPort;
    public RequestAuthenticator(OidcHttpFacade facade, OidcClientConfiguration deployment, int sslRedirectPort) {
        this.facade = facade;
        this.deployment = deployment;
        this.sslRedirectPort = sslRedirectPort;
    }

    public AuthOutcome authenticate() {
        AuthOutcome authenticate = doAuthenticate();
        if (AuthOutcome.AUTHENTICATED.equals(authenticate)) {
            if (! facade.isAuthorized()) {
                return AuthOutcome.FAILED;
            }
        }
        return authenticate;
    }

    protected OidcRequestAuthenticator createOidcAuthenticator() {
        return new OidcRequestAuthenticator(this, facade, deployment, sslRedirectPort, facade.getTokenStore());
    }

    protected void completeOidcAuthentication(final OidcPrincipal<RefreshableOidcSecurityContext> principal) {
        facade.authenticationComplete(new OidcAccount(principal), true);
    }

    protected void completeBearerAuthentication(final OidcPrincipal<RefreshableOidcSecurityContext> principal) {
        facade.authenticationComplete(new OidcAccount(principal), false);
    }

    protected String changeHttpSessionId(boolean create) {
        HttpScope session = facade.getScope(Scope.SESSION);
        if (create) {
            if (! session.exists()) {
                session.create();
            }
        }
        return session != null ? session.getID() : null;
    }

    public AuthChallenge getChallenge() {
        return challenge;
    }

    private AuthOutcome doAuthenticate() {
        if (log.isTraceEnabled()) {
            log.trace("--> authenticate()");
        }

        if (log.isTraceEnabled()) {
            log.trace("try bearer");
        }

        BearerTokenRequestAuthenticator bearer = new BearerTokenRequestAuthenticator(facade, deployment);

        AuthOutcome outcome = bearer.authenticate();
        if (outcome == AuthOutcome.FAILED) {
            challenge = bearer.getChallenge();
            log.debug("Bearer FAILED");
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.AUTHENTICATED) {
            if (verifySSL()) return AuthOutcome.FAILED;
            completeAuthentication(bearer);
            log.debug("Bearer AUTHENTICATED");
            return AuthOutcome.AUTHENTICATED;
        }

        QueryParameterTokenRequestAuthenticator queryParamAuth = new QueryParameterTokenRequestAuthenticator(facade, deployment);
        if (log.isTraceEnabled()) {
            log.trace("try query parameter auth");
        }

        outcome = queryParamAuth.authenticate();
        if (outcome == AuthOutcome.FAILED) {
            challenge = queryParamAuth.getChallenge();
            log.debug("QueryParamAuth auth FAILED");
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.AUTHENTICATED) {
            if (verifySSL()) return AuthOutcome.FAILED;
            log.debug("QueryParamAuth AUTHENTICATED");
            completeAuthentication(queryParamAuth);
            return AuthOutcome.AUTHENTICATED;
        }

        if (deployment.isEnableBasicAuth()) {
            BasicAuthRequestAuthenticator basicAuth = new BasicAuthRequestAuthenticator(facade, deployment);
            if (log.isTraceEnabled()) {
                log.trace("try basic auth");
            }

            outcome = basicAuth.authenticate();
            if (outcome == AuthOutcome.FAILED) {
                challenge = basicAuth.getChallenge();
                log.debug("BasicAuth FAILED");
                return AuthOutcome.FAILED;
            } else if (outcome == AuthOutcome.AUTHENTICATED) {
                if (verifySSL()) return AuthOutcome.FAILED;
                log.debug("BasicAuth AUTHENTICATED");
                completeAuthentication(basicAuth);
                return AuthOutcome.AUTHENTICATED;
            }
        }

        if (deployment.isBearerOnly()) {
            challenge = bearer.getChallenge();
            log.debug("NOT_ATTEMPTED: bearer only");
            return AuthOutcome.NOT_ATTEMPTED;
        }

        if (log.isTraceEnabled()) {
            log.trace("try oidc");
        }

        if (facade.getTokenStore().isCached(this)) {
            if (verifySSL()) return AuthOutcome.FAILED;
            log.debug("AUTHENTICATED: was cached");
            return AuthOutcome.AUTHENTICATED;
        }

        if (isAutodetectedBearerOnly()) {
            challenge = bearer.getChallenge();
            log.debug("NOT_ATTEMPTED: Treating as bearer only");
            return AuthOutcome.NOT_ATTEMPTED;
        }

        OidcRequestAuthenticator oidc = createOidcAuthenticator();
        outcome = oidc.authenticate();
        if (outcome == AuthOutcome.FAILED) {
            challenge = oidc.getChallenge();
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.NOT_ATTEMPTED) {
            challenge = oidc.getChallenge();
            return AuthOutcome.NOT_ATTEMPTED;
        }

        if (verifySSL()) return AuthOutcome.FAILED;

        completeAuthentication(oidc);

        // redirect to strip out access code and state query parameters
        facade.getResponse().setHeader("Location", oidc.getStrippedOauthParametersRequestUri());
        facade.getResponse().setStatus(302);
        facade.getResponse().end();

        log.debug("AUTHENTICATED");
        return AuthOutcome.AUTHENTICATED;
    }

    protected boolean verifySSL() {
        if (!facade.getRequest().isSecure() && deployment.getSSLRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            log.warnf("SSL is required to authenticate. Remote address %s is secure: %s, SSL required for: %s .",
                    facade.getRequest().getRemoteAddr(), facade.getRequest().isSecure(), deployment.getSSLRequired().name());
            return true;
        }
        return false;
    }

    protected void completeAuthentication(OidcRequestAuthenticator oidc) {
        RefreshableOidcSecurityContext session = new RefreshableOidcSecurityContext(deployment, facade.getTokenStore(), oidc.getTokenString(), oidc.getToken(), oidc.getIDTokenString(), oidc.getIDToken(), oidc.getRefreshToken());
        final OidcPrincipal<RefreshableOidcSecurityContext> principal = new OidcPrincipal<>(oidc.getIDToken().getPrincipalName(deployment), session);
        completeOidcAuthentication(principal);
        log.debugv("User ''{0}'' invoking ''{1}'' on client ''{2}''", principal.getName(), facade.getRequest().getURI(), deployment.getResourceName());
    }

    protected void completeAuthentication(BearerTokenRequestAuthenticator bearer) {
        RefreshableOidcSecurityContext session = new RefreshableOidcSecurityContext(deployment, null, bearer.getTokenString(), bearer.getToken(), null, null, null);
        final OidcPrincipal<RefreshableOidcSecurityContext> principal = new OidcPrincipal<>(bearer.getToken().getPrincipalName(deployment), session);
        completeBearerAuthentication(principal);
        log.debugv("User ''{0}'' invoking ''{1}'' on client ''{2}''", principal.getName(), facade.getRequest().getURI(), deployment.getResourceName());
    }

    protected boolean isAutodetectedBearerOnly() {
        if (! deployment.isAutodetectBearerOnly()) return false;

        String headerValue = facade.getRequest().getHeader(X_REQUESTED_WITH);
        if (headerValue != null && headerValue.equalsIgnoreCase(XML_HTTP_REQUEST)) {
            return true;
        }
        headerValue = facade.getRequest().getHeader(FACES_REQUEST);
        if (headerValue != null && headerValue.startsWith(PARTIAL)) {
            return true;
        }
        headerValue = facade.getRequest().getHeader(SOAP_ACTION);
        if (headerValue != null) {
            return true;
        }

        List<String> accepts = facade.getRequest().getHeaders(ACCEPT);
        if (accepts == null) accepts = Collections.emptyList();
        for (String accept : accepts) {
            if (accept.contains(HTML_CONTENT_TYPE) || accept.contains(TEXT_CONTENT_TYPE) || accept.contains(WILDCARD_CONTENT_TYPE)) {
                return false;
            }
        }
        return true;
    }
}
