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

package org.wildfly.security.auth.realm.token._private;

import static org.jboss.logging.Logger.Level.WARN;

import java.net.URL;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.auth.server.RealmUnavailableException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 1104, max = 1180),
    @ValidIdRange(min = 1181, max = 1185)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 1104, value = "OAuth2-based realm failed to obtain principal")
    RuntimeException tokenRealmFailedToObtainPrincipal(@Cause Throwable cause);

    @Message(id = 1105, value = "OAuth2-based realm failed to introspect token")
    RealmUnavailableException tokenRealmOAuth2TokenIntrospectionFailed(@Cause Throwable cause);

    @Message(id = 1113, value = "Token-based realm failed to obtain principal from token using claim [%s]")
    IllegalStateException tokenRealmFailedToObtainPrincipalWithClaim(String claimName);

    @Message(id = 1114, value = "Invalid token format. Tokens must have a signature part accordingly with JWS specification")
    IllegalArgumentException tokenRealmJwtInvalidFormat();

    @Message(id = 1115, value = "Failed to parse token")
    IllegalStateException tokenRealmJwtParseFailed(@Cause Throwable cause);

    @Message(id = 1116, value = "Signature verification failed")
    IllegalStateException tokenRealmJwtSignatureCheckFailed(@Cause Throwable cause);

    @Message(id = 1117, value = "Invalid signature algorithm [%s]")
    IllegalArgumentException tokenRealmJwtSignatureInvalidAlgorithm(String algorithm);

    @Message(id = 1118, value = "Public key could not be obtained. Probably due to an invalid PEM format.")
    IllegalArgumentException tokenRealmJwtInvalidPublicKeyPem();

    @LogMessage(level = WARN)
    @Message(id = 1126, value = "Jwt-based token realm not configured with a list of valid issuers. Ignoring issuer verification.")
    void tokenRealmJwtWarnNoIssuerIgnoringIssuerCheck();

    @LogMessage(level = WARN)
    @Message(id = 1127, value = "Jwt-based token not configured with a list of valid audiences. Ignoring audience verification.")
    void tokenRealmJwtWarnNoAudienceIgnoringAudienceCheck();

    @LogMessage(level = WARN)
    @Message(id = 1128, value = "Jwt-based token not configured with a public key. Ignoring signature verification.")
    void tokenRealmJwtWarnNoPublicKeyIgnoringSignatureCheck();

    @LogMessage(level = WARN)
    @Message(id = 1178, value = "Unable to update jwk set from \"%1$s\".")
    void unableToFetchJwks(String url);

    @LogMessage(level = WARN)
    @Message(id = 1179, value = "SSL not configured. jku claim will not be supported.")
    void tokenRealmJwtNoSSLIgnoringJku();

    @LogMessage
    @Message(id = 1180, value = "Fetched jwk does not contain \"%1$s\" claim, ignoring...")
    void tokenRealmJwkMissingClaim(String claim);

    @LogMessage(level = WARN)
    @Message(id = 1181, value = "Not sending new request to jwks url \"%s\". Last request time was %d.")
    void avoidingFetchJwks(URL url, long timestamp);

    @LogMessage(level = WARN)
    @Message(id = 1182, value = "Allowed jku values haven't been configured for the JWT validator. Token validation will fail if the token contains a 'jku' header parameter.")
    void allowedJkuValuesNotConfigured();
}

