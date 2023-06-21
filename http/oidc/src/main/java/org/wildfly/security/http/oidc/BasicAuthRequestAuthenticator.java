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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.wildfly.common.array.Arrays2.indexOf;
import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.NO_TOKEN;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.List;

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.http.HttpConstants;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class BasicAuthRequestAuthenticator extends BearerTokenRequestAuthenticator {

    private static final String CHALLENGE_PREFIX = "Basic ";

    public BasicAuthRequestAuthenticator(OidcHttpFacade facade, OidcClientConfiguration oidcClientConfiguration) {
        super(facade, oidcClientConfiguration);
    }

    public Oidc.AuthOutcome authenticate()  {
        List<String> authorizationValues = facade.getRequest().getHeaders(HttpConstants.AUTHORIZATION);
        if (authorizationValues == null || authorizationValues.isEmpty()) {
            challenge = challengeResponse(AuthenticationError.Reason.NO_AUTHORIZATION_HEADER, null, null);
            return Oidc.AuthOutcome.NOT_ATTEMPTED;
        }

        String basicValue = null;
        for (String authorizationValue : authorizationValues) {
            if (authorizationValue.regionMatches(true, 0, CHALLENGE_PREFIX, 0, CHALLENGE_PREFIX.length())) {
                basicValue = authorizationValue.substring(CHALLENGE_PREFIX.length());
                break;
            }
        }
        if (basicValue == null) {
            challenge = challengeResponse(AuthenticationError.Reason.INVALID_TOKEN, null, null);
            return Oidc.AuthOutcome.NOT_ATTEMPTED;
        }
        byte[] decodedValue = ByteIterator.ofBytes(basicValue.getBytes(UTF_8)).asUtf8String().base64Decode().drain();
        int colonPos = indexOf(decodedValue, ':');
        if (colonPos <= 0) {
            log.debug("Failed to obtain token");
            challenge = challengeResponse(AuthenticationError.Reason.INVALID_TOKEN, NO_TOKEN, null);
            return Oidc.AuthOutcome.FAILED;
        }

        ByteBuffer usernameBytes = ByteBuffer.wrap(decodedValue, 0, colonPos);
        ByteBuffer passwordBytes = ByteBuffer.wrap(decodedValue, colonPos + 1, decodedValue.length - colonPos - 1);
        CharBuffer usernameChars = UTF_8.decode(usernameBytes);
        CharBuffer passwordChars = UTF_8.decode(passwordBytes);
        AccessAndIDTokenResponse tokenResponse;
        try {
            String username = usernameChars.toString();
            String password = passwordChars.toString();
            tokenResponse = ServerRequest.getBearerToken(oidcClientConfiguration, username, password);
        } catch (Exception e) {
            log.debug("Failed to obtain token");
            challenge = challengeResponse(AuthenticationError.Reason.INVALID_TOKEN, NO_TOKEN, e.getMessage());
            return Oidc.AuthOutcome.FAILED;
        }
        tokenString = tokenResponse.getAccessToken();
        return verifyToken(tokenString);
    }

}
