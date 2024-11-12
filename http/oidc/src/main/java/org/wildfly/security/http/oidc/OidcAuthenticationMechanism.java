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
import static org.wildfly.security.http.oidc.Oidc.OIDC_CLIENT_CONTEXT_KEY;
import static org.wildfly.security.http.oidc.Oidc.AuthOutcome;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;
import static org.wildfly.security.http.oidc.Oidc.OPTIONS;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.apache.http.HttpStatus;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;

/**
 * An {@link HttpServerAuthenticationMechanism} to support OpenID Connect (OIDC).
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class OidcAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private static LogoutHandler logoutHandler = new LogoutHandler();

    private final Map<String, ?> properties;
    private final CallbackHandler callbackHandler;
    private final OidcClientContext oidcClientContext;

    OidcAuthenticationMechanism(Map<String, ?> properties, CallbackHandler callbackHandler, OidcClientContext oidcClientContext) {
        this.properties = properties;
        this.callbackHandler = callbackHandler;
        this.oidcClientContext = oidcClientContext;
    }

    @Override
    public String getMechanismName() {
        return OIDC_NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        String tmpURI = request.getRequestURI().toString();
        OidcClientContext oidcClientContext = getOidcClientContext(request);
        if (oidcClientContext == null) {
            log.debugf("Ignoring request for path [%s] from mechanism [%s]. No client configuration context found.", request.getRequestURI(), getMechanismName());
            request.noAuthenticationInProgress();
            return;
        }

        OidcHttpFacade httpFacade = new OidcHttpFacade(request, oidcClientContext, callbackHandler);
        OidcClientConfiguration oidcClientConfiguration = httpFacade.getOidcClientConfiguration();
        if (! oidcClientConfiguration.isConfigured()) {
            request.noAuthenticationInProgress();
            return;
        }

        RequestAuthenticator authenticator = createRequestAuthenticator(httpFacade, oidcClientConfiguration);
        httpFacade.getTokenStore().checkCurrentToken();
        if ((oidcClientConfiguration.getAuthServerBaseUrl() != null && keycloakPreActions(httpFacade, oidcClientConfiguration))
                || preflightCors(httpFacade, oidcClientConfiguration)) {
            log.debugf("Pre-actions has aborted the evaluation of [%s]", request.getRequestURI());
            httpFacade.authenticationInProgress();
            return;
        }

        AuthOutcome outcome = authenticator.authenticate();
        if (AuthOutcome.AUTHENTICATED.equals(outcome)) {
            if (new AuthenticatedActionsHandler(oidcClientConfiguration, httpFacade).handledRequest()
            ) {
                httpFacade.authenticationInProgress();
            } else {
                httpFacade.authenticationComplete();
            }
            return;
        }

        AuthChallenge challenge = authenticator.getChallenge();
        if (challenge != null) {
            httpFacade.noAuthenticationInProgress(challenge);
            return;
        }
        if (Oidc.AuthOutcome.FAILED.equals(outcome)) {
            httpFacade.getResponse().setStatus(HttpStatus.SC_FORBIDDEN);
            httpFacade.authenticationFailed();
            return;
        }
        httpFacade.noAuthenticationInProgress();
    }

    private RequestAuthenticator createRequestAuthenticator(OidcHttpFacade httpFacade, OidcClientConfiguration deployment) {
        return new RequestAuthenticator(httpFacade, deployment, getConfidentialPort());
    }

    private OidcClientContext getOidcClientContext(HttpServerRequest request) {
        if (this.oidcClientContext == null) {
            return (OidcClientContext) request.getScope(Scope.APPLICATION).getAttachment(OIDC_CLIENT_CONTEXT_KEY);
        }
        return this.oidcClientContext;
    }

    private int getConfidentialPort() {
        return 8443;
    }

    private boolean keycloakPreActions(OidcHttpFacade httpFacade, OidcClientConfiguration oidcClientConfiguration) {
        NodesRegistrationManagement nodesRegistrationManagement = new NodesRegistrationManagement();
        nodesRegistrationManagement.tryRegister(oidcClientConfiguration);
        return false;
    }

    private boolean preflightCors(OidcHttpFacade httpFacade, OidcClientConfiguration oidcClientConfiguration) {
        String requestUri = httpFacade.getRequest().getURI();
        log.debugv("adminRequest {0}", requestUri);
        if (! oidcClientConfiguration.isCors()) {
            return false;
        }
        log.debugv("checkCorsPreflight {0}", httpFacade.getRequest().getURI());
        if (! httpFacade.getRequest().getMethod().equalsIgnoreCase(OPTIONS)) {
            return false;
        }
        String origin = httpFacade.getRequest().getHeader(CorsHeaders.ORIGIN);
        if (origin == null) {
            log.debug("checkCorsPreflight: no origin header");
            return false;
        }
        log.debug("Preflight request returning");
        httpFacade.getResponse().setStatus(HttpStatus.SC_OK);
        httpFacade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        httpFacade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        String requestMethods = httpFacade.getRequest().getHeader(CorsHeaders.ACCESS_CONTROL_REQUEST_METHOD);
        if (requestMethods != null) {
            if (oidcClientConfiguration.getCorsAllowedMethods() != null) {
                requestMethods = oidcClientConfiguration.getCorsAllowedMethods();
            }
            httpFacade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_METHODS, requestMethods);
        }
        String allowHeaders = httpFacade.getRequest().getHeader(CorsHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
        if (allowHeaders != null) {
            if (oidcClientConfiguration.getCorsAllowedHeaders() != null) {
                allowHeaders = oidcClientConfiguration.getCorsAllowedHeaders();
            }
            httpFacade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_HEADERS, allowHeaders);
        }
        if (oidcClientConfiguration.getCorsMaxAge() > -1) {
            httpFacade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_MAX_AGE, Integer.toString(oidcClientConfiguration.getCorsMaxAge()));
        }
        return true;
    }

}
