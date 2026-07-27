/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.oidc;

import static org.jboss.logging.annotations.Message.NONE;
import static org.jboss.logging.Logger.Level.DEBUG;
import static org.jboss.logging.Logger.Level.ERROR;
import static org.jboss.logging.Logger.Level.WARN;

import java.io.IOException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
        @ValidIdRange(min = 23000, max = 23999)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.oidc");

    @Message(id = 23000, value = "Unexpected HTTP status code in response from OIDC provider \"%d\"")
    OidcException unexpectedResponseCodeFromOidcProvider(int responseCode);

    @Message(id = 23001, value = "No entity in response from OIDC provider")
    OidcException noEntityInResponse();

    @Message(id = 23002, value = "Unexpected error sending request to OIDC provider")
    OidcException unexpectedErrorSendingRequestToOidcProvider(@Cause Exception cause);

    @Message(id = 23003, value = "Either provider-url or auth-server-url needs to be configured")
    IllegalArgumentException providerUrlOrAuthServerUrlNeedsToBeConfigured();

    @LogMessage
    @Message(id = 23004, value = "Loaded OpenID provider metadata from '%s'")
    void loadedOpenIdProviderMetadata(String discoveryUrl);

    @LogMessage(level = WARN)
    @Message(id = 23005, value = "Unable to load OpenID provider metadata from %s")
    void unableToLoadOpenIdProviderMetadata(String discoveryUrl);

    @Message(id = 23006, value = "Failed to decode request URI")
    RuntimeException failedToDecodeRequestUri(@Cause Exception cause);

    @Message(id = 23007, value = "Failed to write to response output stream")
    RuntimeException failedToWriteToResponseOutputStream(@Cause Exception cause);

    @Message(id = 23008, value = "Unable to parse token")
    IllegalArgumentException unableToParseToken();

    @Message(id = 23009, value = "OIDC client configuration file not found")
    RuntimeException oidcConfigFileNotFound(@Cause Exception cause);

    @LogMessage(level = ERROR)
    @Message(id = 23010, value = "Failed to invoke remote logout")
    void failedToInvokeRemoteLogout(@Cause Throwable cause);

    @LogMessage(level = ERROR)
    @Message(id = 23011, value = "Refresh token failure")
    void refreshTokenFailure(@Cause Throwable cause);

    @LogMessage(level = DEBUG)
    @Message(id = 23012, value = "Refresh token failure status: %d %s")
    void refreshTokenFailureStatus(int status, String error);

    @LogMessage(level = DEBUG)
    @Message(id = 23013, value = "Failed verification of token: %s")
    void failedVerificationOfToken(String error);

    @LogMessage(level = ERROR)
    @Message(id = 23014, value = "Failed to refresh the token with a longer time-to-live than the minimum")
    void failedToRefreshTokenWithALongerTTLThanMin();

    @Message(id = 23015, value = "No expected issuer given")
    IllegalArgumentException noExpectedIssuerGiven();

    @Message(id = 23016, value = "No client ID given")
    IllegalArgumentException noClientIDGiven();

    @Message(id = 23017, value = "No expected JWS algorithm given")
    IllegalArgumentException noExpectedJwsAlgorithmGiven();

    @Message(id = 23018, value = "No JWKS public key or client secret key given")
    IllegalArgumentException noJwksPublicKeyOrClientSecretKeyGiven();

    @Message(id = 23019, value = "Invalid ID token")
    OidcException invalidIDToken(@Cause Throwable cause);

    @Message(id = NONE, value = "Unexpected value for azp (issued for) claim")
    String unexpectedValueForIssuedForClaim();

    @Message(id = 23020, value = "Invalid token claim value")
    IllegalArgumentException invalidTokenClaimValue();

    @Message(id = 23021, value = "Invalid ID token claims")
    OidcException invalidIDTokenClaims();

    @Message(id = 23022, value = "Must set 'realm' in config")
    RuntimeException keycloakRealmMissing();

    @Message(id = 23023, value = "Must set 'resource' or 'client-id'")
    RuntimeException resourceOrClientIdMustBeSet();

    @Message(id = 23024, value = "For bearer auth, you must set the 'realm-public-key' or one of 'auth-server-url' and 'provider-url'")
    IllegalArgumentException invalidConfigurationForBearerAuth();

    @Message(id = 23025, value = "Must set 'auth-server-url' or 'provider-url'")
    RuntimeException authServerUrlOrProviderUrlMustBeSet();

    @LogMessage(level = WARN)
    @Message(id = 23026, value = "Client '%s' does not have a secret configured")
    void noClientSecretConfigured(String clientId);

    @Message(id = 23027, value = "Unsupported public key")
    IllegalArgumentException unsupportedPublicKey();

    @Message(id = 23028, value = "Unable to create signed token")
    IllegalArgumentException unableToCreateSignedToken();

    @Message(id = 23029, value = "Configuration of jwt credentials is missing or incorrect for client '%s'")
    RuntimeException invalidJwtClientCredentialsConfig(String clientId);

    @Message(id = 23030, value = "Missing parameter '%s' in jwt credentials for client %s")
    RuntimeException missingParameterInJwtClientCredentialsConfig(String parameter, String clientId);

    @Message(id = 23031, value = "Unable to parse key '%s' with value '%s'")
    IllegalArgumentException unableToParseKeyWithValue(String key, Object value);

    @Message(id = 23032, value = "Unable to load key with alias '%s' from keystore")
    RuntimeException unableToLoadKeyWithAlias(String alias);

    @Message(id = 23033, value = "Unable to load private key from keystore")
    RuntimeException unableToLoadPrivateKey(@Cause Throwable cause);

    @Message(id = 23034, value = "Unable to find keystore file '%s'")
    RuntimeException unableToFindKeystoreFile(String keystoreFile);

    @Message(id = 23035, value = "Configuration of secret jwt client credentials is missing or incorrect for client '%s'")
    RuntimeException invalidJwtClientCredentialsUsingSecretConfig(String clientId);

    @Message(id = 23036, value = "Invalid value for 'algorithm' in secret jwt client credentials configuration for client '%s'")
    RuntimeException invalidAlgorithmInJwtClientCredentialsConfig(String clientId);

    @Message(id = 23037, value = "Unable to determine client credentials provider type for client '%s'")
    RuntimeException unableToDetermineClientCredentialsProviderType(String clientId);

    @Message(id = 23038, value = "Unable to find client credentials provider '%s'")
    RuntimeException unableToFindClientCredentialsProvider(String provider);

    @Message(id = 23039, value = "Unable to load keystore")
    RuntimeException unableToLoadKeyStore(@Cause Throwable cause);

    @Message(id = 23040, value = "Unable to load truststore")
    RuntimeException unableToLoadTrustStore(@Cause Throwable cause);

    @Message(id = 23041, value = "Unable to find truststore file '%s'")
    RuntimeException unableToFindTrustStoreFile(String trustStoreFile);

    @Message(id = 23042, value = "Unexpected value for at_hash claim")
    String unexpectedValueForAtHashClaim();

    @Message(id = 23043, value = "Uknown algorithm: '%s'")
    IllegalArgumentException unknownAlgorithm(String algorithm);

    @LogMessage(level = WARN)
    @Message(id = 23044, value = "Failed to parse token from cookie")
    void failedToParseTokenFromCookie(@Cause Throwable cause);

    @Message(id = 23045, value = "Unable to create redirect response")
    IllegalArgumentException unableToCreateRedirectResponse(@Cause Throwable cause);

    @Message(id = 23046, value = "Unable to set auth server URL")
    RuntimeException unableToSetAuthServerUrl(@Cause Throwable cause);

    @Message(id = 23047, value = "Unable resolve a relative URL")
    RuntimeException unableToResolveARelativeUrl();

    @Message(id = 23048, value = "Invalid URI: '%s'")
    RuntimeException invalidUri(String uri);

    @LogMessage(level = WARN)
    @Message(id = 23049, value = "Invalid 'auth-server-url' or 'provider-url': '%s'")
    void invalidAuthServerUrlOrProviderUrl(String url);

    @Message(id = 23050, value = "Invalid bearer token")
    OidcException invalidBearerToken(@Cause Throwable cause);

    @Message(id = 23051, value = "Invalid token claims")
    OidcException invalidTokenClaims();

    @LogMessage(level = WARN)
    @Message(id = 23052, value = "No trusted certificates in token")
    void noTrustedCertificatesInToken();

    @LogMessage(level = WARN)
    @Message(id = 23053, value = "No peer certificates established on the connection")
    void noPeerCertificatesEstablishedOnConnection();

    @Message(id = 23054, value = "Unexpected value for typ claim")
    String unexpectedValueForTypeClaim();

    @Message(id = 23055, value = "Unable to obtain token: %d")
    IOException unableToObtainToken(int status);

    @Message(id = 23056, value = "No message entity")
    IOException noMessageEntity();

    @LogMessage(level = DEBUG)
    @Message(id = 23057, value = "principal-attribute '%s' claim does not exist, falling back to 'sub'")
    void principalAttributeClaimDoesNotExist(String principalAttributeClaim);

    @Message(id = 23058, value = "Invalid keystore configuration for signing Request Objects.")
    IOException invalidKeyStoreConfiguration();

    @Message(id = 23059, value = "The signature algorithm specified is not supported by the OpenID Provider.")
    IOException invalidRequestObjectSignatureAlgorithm();

    @Message(id = 23060, value = "The encryption algorithm specified is not supported by the OpenID Provider.")
    IOException invalidRequestObjectEncryptionAlgorithm();

    @Message(id = 23061, value = "The content encryption algorithm (enc value) specified is not supported by the OpenID Provider.")
    IOException invalidRequestObjectEncryptionEncValue();

    @LogMessage(level = WARN)
    @Message(id = 23062, value = "The OpenID provider does not support request parameters. Sending the request using OAuth2 format.")
    void requestParameterNotSupported();

    @Message(id = 23063, value = "Both request object encryption algorithm and request object content encryption algorithm must be configured to encrypt the request object.")
    IllegalArgumentException invalidRequestObjectEncryptionAlgorithmConfiguration();

    @Message(id = 23064, value = "Failed to create the authentication request using the request parameter.")
    RuntimeException unableToCreateRequestWithRequestParameter(@Cause Exception cause);

    @Message(id = 23065, value = "Failed to create the authentication request using the request_uri parameter.")
    RuntimeException unableToCreateRequestUriWithRequestParameter(@Cause Exception cause);

    @Message (id = 23066, value = "Failed to send a request to the OpenID provider's Pushed Authorization Request endpoint.")
    RuntimeException failedToSendPushedAuthorizationRequest(@Cause Exception cause);

    @Message(id = 23067, value = "Cannot retrieve the request_uri as the pushed authorization request endpoint is not available for the OpenID provider.")
    RuntimeException pushedAuthorizationRequestEndpointNotAvailable();

    @LogMessage(level = WARN)
    @Message(id = 23068, value = "The request object will be unsigned. This should not be used in a production environment. To sign the request object, for use in a production environment, please specify the request object signing algorithm.")
    void unsignedRequestObjectIsUsed();

    @Message(id = 23069, value = "The client secret has not been configured. Unable to sign the request object using the client secret.")
    RuntimeException clientSecretNotConfigured();

    @Message(id = 23070, value = "Authentication request format must be one of the following: oauth2, request, request_uri.")
    RuntimeException invalidAuthenticationRequestFormat();

    @Message(id = 23071, value = "Invalid ID token nonce: %s")
    String invalidNonceValue(String name);

    @Message(id = 23072, value = "No such algorithm: '%s'")
    IllegalArgumentException noSuchAlgorithm(String algorithm);

    @Message(id = 23073, value = "Nonce cookie does not exist")
    String nonceCookieDoesNotExist();

    @Message(id = 23074, value = "Invalid logout path: %s is not a valid value for %s")
    IllegalArgumentException invalidLogoutPath(String pathValue, String pathName);

    @Message(id = 23075, value = "Invalid logout callback path: %s is not a valid relative path or absolute http(s) URI for %s")
    IllegalArgumentException invalidLogoutCallbackPathOrUri(String value, String attributeName);

    @Message(id = 23076, value = "Unable to create end session endpoint request: %s . [%s]")
    RuntimeException unableToCreateEndSessionEndpointRequest(String url, String msg);

    @Message(id = 23077, value = "Back-channel logout request received but can not infer sid from logout token to mark it for invalidation")
    String sidCanNotBeInferredFromLogoutToken();

    @Message(id = 23078, value = "alg claim can not have value none")
    String algClaimCanNotHaveValueNone();

    @Message(id = 23079, value = "Nonce claim is not allowed")
    String nonceClaimIsNotAllowed();

    @Message(id = 23080, value = "An iss claim is required")
    String anIssClaimIsRequired();

    @Message(id = 23081, value = "No matching value found for %s claim")
    String noMatchingValueFoundForClaim(String key);

    @Message(id = 23082, value = "Value for iat claim is before allowed time")
    String valueForIatClaimIsBeforeAllowedTime();

    @Message(id = 23083, value = "Invalid datatype for iat")
    String invalidDatatypeForIat();

    @Message(id = 23084, value = "Events claim does not contain the required member name")
    String eventsClaimDoesNotContainTheRequiredMemberName();

    @Message(id = 23085, value = "Required events claim not found")
    String requiredEventsClaimNotFound();

    @Message(id = 23086, value = "Neither claim sub nor sid is present")
    String neitherClaimSubNorSidIsPresent();

    @Message(id = 23087, value = "MalformedClaimException: %s")
    String malformedClaimException(String e);

    @Message(id = 23088, value = "Required logout claim, %s, is missing")
    String requiredLogoutClaimIsMissing(String e);
}

