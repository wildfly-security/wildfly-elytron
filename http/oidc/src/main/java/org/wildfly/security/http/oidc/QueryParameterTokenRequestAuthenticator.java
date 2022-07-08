/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2022 Red Hat, Inc., and individual contributors
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

/**
 * @author <a href="mailto:froehlich.ch@gmail.com">Christian Froehlich</a>
 * @author <a href="mailto:brad.culley@spartasystems.com">Brad Culley</a>
 * @author <a href="mailto:john.ament@spartasystems.com">John D. Ament</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class QueryParameterTokenRequestAuthenticator extends BearerTokenRequestAuthenticator {
    public static final String ACCESS_TOKEN = "access_token";

    public QueryParameterTokenRequestAuthenticator(OidcHttpFacade facade, OidcClientConfiguration oidcClientConfiguration) {
        super(facade, oidcClientConfiguration);
    }

    public Oidc.AuthOutcome authenticate() {
        if(! oidcClientConfiguration.isOAuthQueryParameterEnabled()) {
            return Oidc.AuthOutcome.NOT_ATTEMPTED;
        }
        tokenString = getAccessTokenFromQueryParameter();
        if (tokenString == null || tokenString.trim().isEmpty()) {
            challenge = challengeResponse(AuthenticationError.Reason.NO_QUERY_PARAMETER_ACCESS_TOKEN, null, null);
            return Oidc.AuthOutcome.NOT_ATTEMPTED;
        }
        return (verifyToken(tokenString));
    }

    String getAccessTokenFromQueryParameter() {
        try {
            if (facade != null && facade.getRequest() != null) {
                return facade.getRequest().getQueryParamValue(ACCESS_TOKEN);
            }
        } catch (Exception ignore) {
        }
        return null;
    }
}
