/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2021 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.server.jwt;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.jwt.NumericDate;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server._private.ElytronMessages;
import org.wildfly.security.credential.AccessTokenCredential;
import org.wildfly.security.credential.RefreshTokenCredential;

/**
 * A utility class to fetch Json Web Tokens, update and revoke them.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class TokenUtil {

    /**
     * Get access token from security identity's private credentials
     * @param securityIdentity the security identity containing the token credentials
     * @return the access token if available or null
     */
    public static String getAccessToken(SecurityIdentity securityIdentity) {
        Assert.assertNotNull(securityIdentity);
        if (securityIdentity.getPrivateCredentials() != null) {
            AccessTokenCredential accessTokenCredential = securityIdentity.getPrivateCredentials().getCredential(AccessTokenCredential.class);
            if (accessTokenCredential != null) return accessTokenCredential.getToken();
        }
        return null;
    }

    /**
     * Get the refresh token from security identity's private credentials
     * @param securityIdentity the security identity containing the token credentials
     * @return the refresh token if available or null
     */
    public static String getRefreshToken(SecurityIdentity securityIdentity) {
        Assert.assertNotNull(securityIdentity);
        if (securityIdentity.getPrivateCredentials() != null) {
            RefreshTokenCredential refreshTokenCredential = securityIdentity.getPrivateCredentials().getCredential(RefreshTokenCredential.class);
            if (refreshTokenCredential != null) return refreshTokenCredential.getToken();
        }
        return null;
    }

    /**
     * Utility method to modify a security identity's private token credentials. It issues a new access
     * or refresh token and stores it as part of the credentials as necessary.
     * @param securityIdentity the security identity holding the current token credentials
     * @return a new security identity with updated token credentials
     * @throws JwtException
     */
    public static SecurityIdentity updateTokenCredentials(SecurityIdentity securityIdentity, TokenProvider tokenProvider) throws JwtException {
        Assert.assertNotNull(securityIdentity);
        String accessToken = getAccessToken(securityIdentity);
        if (accessToken != null) {
            try {
                JsonWebToken accessJwt = tokenProvider.parseAndVerifyAccessToken(accessToken);
                if (accessJwt.getExpirationTime() > NumericDate.now().getValue()) return securityIdentity;
            } catch (JwtException e) {
                ElytronMessages.log.accessTokenIsInvalid();
            }
        }
        String refreshToken = getRefreshToken(securityIdentity);
        if (refreshToken != null) {
            try {
                JsonWebToken refreshJwt = tokenProvider.parseAndVerifyRefreshToken(refreshToken);
                if (refreshJwt.getExpirationTime() > NumericDate.now().getValue()) {
                    String newAccessToken = tokenProvider.issueAccessToken(securityIdentity);
                    return securityIdentity.withPrivateCredential(new AccessTokenCredential(newAccessToken));
                }
            } catch (JwtException e) {
                ElytronMessages.log.refreshTokenIsInvalid();
            }
        }
        // Security identity doesn't have a valid access and refresh token.
        return addTokenCredentials(securityIdentity, tokenProvider);
    }

    /**
     * Issues both an access and refresh token at once and stores them in a new security identity.
     * @param securityIdentity the security identity to add the credentials to
     * @return a new security identity with refresh and access token credentials
     * @throws JwtException
     */
    private static SecurityIdentity addTokenCredentials(SecurityIdentity securityIdentity, TokenProvider tokenProvider) throws JwtException {
        String refreshToken = tokenProvider.issueRefreshToken(securityIdentity);
        String accessToken = tokenProvider.issueAccessToken(securityIdentity);
        SecurityIdentity newIdentity = securityIdentity.withPrivateCredential(new AccessTokenCredential(accessToken));
        return newIdentity.withPrivateCredential(new RefreshTokenCredential(refreshToken));
    }
}
