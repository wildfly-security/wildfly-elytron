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

import static org.wildfly.security.http.HttpConstants.BEARER_TOKEN_PATTERN;
import static org.wildfly.security.http.HttpConstants.ERROR;
import static org.wildfly.security.http.HttpConstants.ERROR_DESCRIPTION;
import static org.wildfly.security.http.HttpConstants.INVALID_TOKEN;
import static org.wildfly.security.http.HttpConstants.REALM;
import static org.wildfly.security.http.HttpConstants.STALE_TOKEN;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;
import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.logToken;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Matcher;

import org.apache.http.HttpStatus;
import org.wildfly.security.http.HttpConstants;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class BearerTokenRequestAuthenticator {
    protected OidcHttpFacade facade;
    protected OidcClientConfiguration oidcClientConfiguration;
    protected AuthChallenge challenge;
    protected String tokenString;
    private AccessToken token;
    private String surrogate;

    public BearerTokenRequestAuthenticator(OidcHttpFacade facade, OidcClientConfiguration oidcClientConfiguration) {
        this.facade = facade;
        this.oidcClientConfiguration = oidcClientConfiguration;
    }

    public AuthChallenge getChallenge() {
        return challenge;
    }

    public String getTokenString() {
        return tokenString;
    }

    public AccessToken getToken() {
        return token;
    }

    public String getSurrogate() {
        return surrogate;
    }

    public Oidc.AuthOutcome authenticate() {
        List<String> authorizationValues = facade.getRequest().getHeaders(HttpConstants.AUTHORIZATION);
        if (authorizationValues == null || authorizationValues.isEmpty()) {
            challenge = challengeResponse(AuthenticationError.Reason.NO_BEARER_TOKEN, null, null);
            return Oidc.AuthOutcome.NOT_ATTEMPTED;
        }

        Matcher matcher;
        for (String authorizationValue : authorizationValues) {
            if ((matcher = BEARER_TOKEN_PATTERN.matcher(authorizationValue)).matches()) {
                tokenString = matcher.group(1);
                log.debugf("Found [%d] values in authorization header, selecting the first value for Bearer", (Integer) authorizationValues.size());
                break;
            }
        }
        if (tokenString == null) {
            challenge = challengeResponse(AuthenticationError.Reason.NO_BEARER_TOKEN, null, null);
            return Oidc.AuthOutcome.NOT_ATTEMPTED;
        }
        return verifyToken(tokenString);
    }

    protected Oidc.AuthOutcome verifyToken(final String tokenString) {
        log.debug("Verifying access_token");
        logToken("\taccess_token", tokenString);
        try {
            TokenValidator tokenValidator = TokenValidator.builder(oidcClientConfiguration).build();
            token = tokenValidator.parseAndVerifyToken(tokenString);
            log.debug("Token Verification succeeded!");
        } catch (OidcException e) {
            log.failedVerificationOfToken(e.getMessage());
            challenge = challengeResponse(AuthenticationError.Reason.INVALID_TOKEN, INVALID_TOKEN, e.getMessage());
            return Oidc.AuthOutcome.FAILED;
        }

        if (token.getIssuedAt() < oidcClientConfiguration.getNotBefore()) {
            log.debug("Stale token");
            challenge = challengeResponse(AuthenticationError.Reason.STALE_TOKEN, INVALID_TOKEN, STALE_TOKEN);
            return Oidc.AuthOutcome.FAILED;
        }

        // these are Keycloak-specific checks
        boolean verifyCaller;
        if (oidcClientConfiguration.isUseResourceRoleMappings()) {
            verifyCaller = isVerifyCaller(token.getResourceAccessClaim(oidcClientConfiguration.getResourceName()));
        } else {
            verifyCaller = isVerifyCaller(token.getRealmAccessClaim());
        }
        if (verifyCaller) {
            List<String> trustedCerts = token.getTrustedCertsClaim();
            if (trustedCerts == null || trustedCerts.isEmpty()) {
                log.noTrustedCertificatesInToken();
                challenge = clientCertChallenge();
                return Oidc.AuthOutcome.FAILED;
            }

            // simply make sure mutual TLS auth took place
            Certificate[] chain = facade.getCertificateChain();
            if (chain == null || chain.length == 0) {
                log.noPeerCertificatesEstablishedOnConnection();
                challenge = clientCertChallenge();
                return Oidc.AuthOutcome.FAILED;
            }
            surrogate = ((X509Certificate) chain[0]).getSubjectDN().getName();
        }

        log.debug("Successfully authorized");
        return Oidc.AuthOutcome.AUTHENTICATED;
    }

    private boolean isVerifyCaller(RealmAccessClaim accessClaim) {
        if (accessClaim != null && accessClaim.getVerifyCaller() != null) {
            return accessClaim.getVerifyCaller().booleanValue();
        }
        return false;
    }

    protected AuthChallenge challengeResponse(final AuthenticationError.Reason reason, final String error, final String description) {
        StringBuilder header = new StringBuilder("Bearer");
        if (oidcClientConfiguration.getRealm() != null) {
            header.append(" ").append(REALM).append("=\"").append(oidcClientConfiguration.getRealm()).append("\"");
            if (error != null || description != null) {
                header.append(",");
            }
        }
        if (error != null) {
            header.append(" ").append(ERROR).append("=\"").append(error).append("\"");
            if (description != null) {
                header.append(",");
            }
        }
        if (description != null) {
            header.append(" ").append(ERROR_DESCRIPTION).append("=\"").append(description).append("\"");
        }

        final String challenge = header.toString();
        return new AuthChallenge() {
            @Override
            public int getResponseCode() {
                return HttpStatus.SC_UNAUTHORIZED;
            }

            @Override
            public boolean challenge(OidcHttpFacade facade) {
                AuthenticationError error = new AuthenticationError(reason, description);
                facade.getRequest().setError(error);
                facade.getResponse().addHeader(WWW_AUTHENTICATE, challenge);
                if(oidcClientConfiguration.isDelegateBearerErrorResponseSending()){
                    facade.getResponse().setStatus(HttpStatus.SC_UNAUTHORIZED);
                }
                else {
                    facade.getResponse().sendError(HttpStatus.SC_UNAUTHORIZED);
                }
                return true;
            }
        };
    }

    protected AuthChallenge clientCertChallenge() {
        return new AuthChallenge() {
            @Override
            public int getResponseCode() {
                return 0;
            }

            @Override
            public boolean challenge(OidcHttpFacade facade) {
                // do the same thing as client cert auth
                return false;
            }
        };
    }

}
