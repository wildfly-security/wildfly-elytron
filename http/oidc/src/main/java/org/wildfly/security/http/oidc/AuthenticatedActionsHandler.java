/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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
import static org.wildfly.security.http.oidc.Oidc.KEYCLOAK_QUERY_BEARER_TOKEN;

import java.io.IOException;
import java.util.List;

/**
 * Pre-installed actions that must be authenticated
 *
 * Actions include:
 *
 * CORS Origin Check and Response headers
 * k_query_bearer_token: Get bearer token from server for Javascripts CORS requests
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class AuthenticatedActionsHandler {

    private static LogoutHandler logoutHandler = new LogoutHandler();
    private OidcClientConfiguration deployment;
    private OidcHttpFacade facade;

    public AuthenticatedActionsHandler(OidcClientConfiguration deployment, OidcHttpFacade facade) {
        this.deployment = deployment;
        this.facade = facade;
    }

    public boolean handledRequest() {
        log.debugv("AuthenticatedActionsValve.invoke {0}", facade.getRequest().getURI());
        if (corsRequest()) return true;
        String requestUri = facade.getRequest().getURI();
        if (requestUri.endsWith(KEYCLOAK_QUERY_BEARER_TOKEN)) {
            queryBearerToken();
            return true;
        }

        if (logoutHandler.tryLogout(facade)) {
            return true;
        }

        return false;
    }

    protected void queryBearerToken()  {
        log.debugv("queryBearerToken {0}",facade.getRequest().getURI());
        if (abortTokenResponse()) return;
        facade.getResponse().setStatus(200);
        facade.getResponse().setHeader("Content-Type", "text/plain");
        try {
            facade.getResponse().getOutputStream().write(facade.getSecurityContext().getTokenString().getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        facade.getResponse().end();
    }

    protected boolean abortTokenResponse() {
        if (facade.getSecurityContext() == null) {
            log.debugv("Not logged in, sending back 401: {0}",facade.getRequest().getURI());
            facade.getResponse().sendError(401);
            facade.getResponse().end();
            return true;
        }
        if (!deployment.isExposeToken()) {
            facade.getResponse().setStatus(200);
            facade.getResponse().end();
            return true;
        }
        // Don't allow a CORS request if we're not validating CORS requests
        String origin = facade.getRequest().getHeader(CorsHeaders.ORIGIN);
        if (! deployment.isCors() && origin != null && ! origin.equals("null")) {
            facade.getResponse().setStatus(200);
            facade.getResponse().end();
            return true;
        }
        return false;
    }

    protected boolean corsRequest()  {
        if (! deployment.isCors()) return false;
        OidcSecurityContext securityContext = facade.getSecurityContext();
        String origin = facade.getRequest().getHeader(CorsHeaders.ORIGIN);
        origin = "null".equals(origin) ? null : origin;
        String exposeHeaders = deployment.getCorsExposedHeaders();

        String requestOrigin = getOrigin(facade.getRequest().getURI());
        log.debugv("Origin: {0} uri: {1}", origin, facade.getRequest().getURI());
        if (securityContext != null && origin != null && ! origin.equals(requestOrigin)) {
            AccessToken token = securityContext.getToken();
            List<String> allowedOrigins = token.getAllowedOrigins();

            log.debugf("Allowed origins in token: %s", allowedOrigins);

            if (allowedOrigins == null || (!allowedOrigins.contains("*") && !allowedOrigins.contains(origin))) {
                if (allowedOrigins == null) {
                    log.debugv("allowedOrigins was null in token");
                } else {
                    log.debugv("allowedOrigins did not contain origin");
                }
                facade.getResponse().sendError(403);
                facade.getResponse().end();
                return true;
            }
            log.debugv("returning origin: {0}", origin);
            facade.getResponse().setStatus(200);
            facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
            if (exposeHeaders != null) {
                facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, exposeHeaders);
            }
        } else {
            log.debugv("cors validation not needed as we are not a secure session or origin header was null: {0}", facade.getRequest().getURI());
        }
        return false;
    }

    private static String getOrigin(String uri) {
        String u = uri;
        int e = u.indexOf('/', 8);
        return e != -1 ? u.substring(0, u.indexOf('/', 8)) : u;
    }
}
