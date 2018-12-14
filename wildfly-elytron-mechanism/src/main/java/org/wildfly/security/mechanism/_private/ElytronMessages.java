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
package org.wildfly.security.mechanism._private;

import static org.jboss.logging.Logger.Level.WARN;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Param;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.ScramServerErrorCode;
import org.wildfly.security.mechanism.ScramServerException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages sasl = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl");
    ElytronMessages saslAnonymous = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.anonymous");
    ElytronMessages saslDigest = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.digest");
    ElytronMessages saslEntity = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.entity");
    ElytronMessages saslExternal = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.external");
    ElytronMessages saslGs2 = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.gs2");
    ElytronMessages saslGssapi = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.gssapi");
    ElytronMessages saslLocal = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.local");
    ElytronMessages saslOAuth2 = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.oauth2");
    ElytronMessages saslOTP = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.otp");
    ElytronMessages saslPlain = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.plain");
    ElytronMessages saslScram = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.scram");
    ElytronMessages httpSpnego = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.spnego");
    ElytronMessages httpClientCert = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.cert");
    ElytronMessages httpDigest = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.digest");
    ElytronMessages httpUserPass = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.password");
    ElytronMessages httpForm = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.form");
    ElytronMessages httpBearer = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.bearer");
    ElytronMessages httpBasic = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.http.basic");

    @LogMessage(level = WARN)
    @Message(id = 7, value = "Credential destroying failed")
    void credentialDestroyingFailed(@Cause Throwable cause);

    @Message(id = 1151, value = "Evidence Verification Failed.")
    SecurityException authenticationFailedEvidenceVerification();

    @Message(id = 5001, value = "Authentication mechanism exchange received a message after authentication was already complete")
    AuthenticationMechanismException mechMessageAfterComplete();

    @Message(id = 5002, value = "Authentication mechanism user name contains an invalid or disallowed character")
    AuthenticationMechanismException mechUserNameContainsInvalidCharacter();

    @Message(id = 5004, value = "Authentication mechanism authorization failed")
    AuthenticationMechanismException mechAuthorizationFailed(@Cause Throwable cause);

    @Message(id = 5005, value = "Authentication mechanism authentication is not yet complete")
    IllegalStateException mechAuthenticationNotComplete();

    @Message(id = 5006, value = "Authentication mechanism does not support security layer (wrapping/unwrapping)")
    IllegalStateException mechNoSecurityLayer();

    @Message(id = 5007, value = "Invalid authentication mechanism negotiation message received")
    AuthenticationMechanismException mechInvalidMessageReceived();

    @Message(id = 5008, value = "No authentication mechanism login name was given")
    AuthenticationMechanismException mechNoLoginNameGiven();

    @Message(id = 5009, value = "No authentication mechanism password was given")
    AuthenticationMechanismException mechNoPasswordGiven();

    @Message(id = 5010, value = "Authentication mechanism authentication failed due to one or more malformed fields")
    AuthenticationMechanismException mechMalformedFields(@Cause IllegalArgumentException ex);

    @Message(id = 5011, value = "Authentication mechanism message is too long")
    AuthenticationMechanismException mechMessageTooLong();

    @Message(id = 5012, value = "Authentication mechanism server-side authentication failed")
    AuthenticationMechanismException mechServerSideAuthenticationFailed(@Cause Exception e);

    @Message(id = 5013, value = "Authentication mechanism password not verified")
    AuthenticationMechanismException mechPasswordNotVerified();

    @Message(id = 5014, value = "Authentication mechanism authorization failed: \"%s\" running as \"%s\"")
    AuthenticationMechanismException mechAuthorizationFailed(String userName, String authorizationId);

    @Message(id = 5018, value = "Channel binding data changed")
    AuthenticationMechanismException mechChannelBindingChanged();

    @Message(id = 5019, value = "No token was given")
    AuthenticationMechanismException mechNoTokenGiven();

    @Message(id = 5022, value = "Initial challenge must be empty")
    AuthenticationMechanismException mechInitialChallengeMustBeEmpty();

    @Message(id = 5023, value = "Unable to set channel binding")
    AuthenticationMechanismException mechUnableToSetChannelBinding(@Cause Exception e);

    @Message(id = 5024, value = "Failed to determine channel binding status")
    AuthenticationMechanismException mechFailedToDetermineChannelBindingStatus(@Cause Exception e);

    @Message(id = 5025, value = "Mutual authentication not enabled")
    AuthenticationMechanismException mechMutualAuthenticationNotEnabled();

    @Message(id = 5026, value = "Unable to map SASL mechanism name to a GSS-API OID")
    AuthenticationMechanismException mechMechanismToOidMappingFailed(@Cause Exception e);

    @Message(id = 5027, value = "Unable to dispose of GSSContext")
    AuthenticationMechanismException mechUnableToDisposeGssContext(@Cause Exception e);

    @Message(id = 5028, value = "Unable to create name for acceptor")
    AuthenticationMechanismException mechUnableToCreateNameForAcceptor(@Cause Exception e);

    @Message(id = 5029, value = "Unable to create GSSContext")
    AuthenticationMechanismException mechUnableToCreateGssContext(@Cause Exception e);

    @Message(id = 5030, value = "Unable to set GSSContext request flags")
    AuthenticationMechanismException mechUnableToSetGssContextRequestFlags(@Cause Exception e);

    @Message(id = 5031, value = "Unable to accept SASL client message")
    AuthenticationMechanismException mechUnableToAcceptClientMessage(@Cause Exception e);

    @Message(id = 5032, value = "GSS-API mechanism mismatch between SASL client and server")
    AuthenticationMechanismException mechGssApiMechanismMismatch();

    @Message(id = 5033, value = "Channel binding not supported for this SASL mechanism")
    AuthenticationMechanismException mechChannelBindingNotSupported();

    @Message(id = 5034, value = "Channel binding type mismatch between SASL client and server")
    AuthenticationMechanismException mechChannelBindingTypeMismatch();

    @Message(id = 5035, value = "Channel binding not provided by client")
    AuthenticationMechanismException mechChannelBindingNotProvided();

    @Message(id = 5036, value = "Unable to determine peer name")
    AuthenticationMechanismException mechUnableToDeterminePeerName(@Cause Exception e);

    @Message(id = 5037, value = "Authentication mechanism client refuses to initiate authentication")
    AuthenticationMechanismException mechClientRefusesToInitiateAuthentication();

    @Message(id = 5038, value = "Nonces do not match")
    AuthenticationMechanismException mechNoncesDoNotMatch();

    @Message(id = 5039, value = "Invalid length of nonce received")
    AuthenticationMechanismException invalidNonceLength();

    @Message(id = 5040, value = "Iteration count %d is below the minimum of %d")
    AuthenticationMechanismException mechIterationCountIsTooLow(int iterationCount, int minimumIterationCount);

    @Message(id = 5041, value = "Iteration count %d is above the maximum of %d")
    AuthenticationMechanismException mechIterationCountIsTooHigh(int iterationCount, int maximumIterationCount);

    @Message(id = 5043, value = "Invalid server message")
    AuthenticationMechanismException mechInvalidServerMessage();

    @Message(id = 5044, value = "Invalid server message")
    AuthenticationMechanismException mechInvalidServerMessageWithCause(@Cause Throwable cause);

    @Message(id = 5045, value = "Invalid client message")
    AuthenticationMechanismException mechInvalidClientMessage();

    @Message(id = 5046, value = "Invalid client message")
    AuthenticationMechanismException mechInvalidClientMessageWithCause(@Cause Throwable cause);

    @Message(id = 5047, value = "[%s] Authentication mechanism message is for mismatched mechanism \"%s\"")
    AuthenticationMechanismException mechUnmatchedMechanism(String mechName, String otherMechName);

    @Message(id = 5049, value = "Server authenticity cannot be verified")
    AuthenticationMechanismException mechServerAuthenticityCannotBeVerified();

    @Message(id = 5050, value = "Callback handler does not support user name")
    AuthenticationMechanismException mechCallbackHandlerDoesNotSupportUserName(@Cause Throwable cause);

    @Message(id = 5051, value = "Callback handler does not support credential acquisition")
    AuthenticationMechanismException mechCallbackHandlerDoesNotSupportCredentialAcquisition(@Cause Throwable cause);

    @Message(id = 5052, value = "Callback handler does not support authorization")
    AuthenticationMechanismException mechAuthorizationUnsupported(@Cause Throwable cause);

    @Message(id = 5053, value = "Callback handler failed for unknown reason")
    AuthenticationMechanismException mechCallbackHandlerFailedForUnknownReason(@Cause Throwable cause);

    @Message(id = 5055, value = "Authentication rejected (invalid proof)")
    AuthenticationMechanismException mechAuthenticationRejectedInvalidProof();

    @Message(id = 5056, value = "Client sent extra message")
    AuthenticationMechanismException mechClientSentExtraMessage();

    @Message(id = 5057, value = "Server sent extra message")
    AuthenticationMechanismException mechServerSentExtraMessage();

    @Message(id = 5058, value = "Authentication failed")
    AuthenticationMechanismException mechAuthenticationFailed();

    @Message(id = 5060, value = "Empty number")
    NumberFormatException emptyNumber();

    @Message(id = 5061, value = "Invalid numeric character")
    NumberFormatException invalidNumericCharacter();

    @Message(id = 5062, value = "Too big number")
    NumberFormatException tooBigNumber();

    @Message(id = 5063, value = "Cannot get clear password from two way password")
    AuthenticationMechanismException mechCannotGetTwoWayPasswordChars(@Cause Throwable cause);

    @Message(id = 5064, value = "Hashing algorithm not supported")
    AuthenticationMechanismException mechMacAlgorithmNotSupported(@Cause Throwable cause);

    @Message(id = 5065, value = "keyword cannot be empty")
    AuthenticationMechanismException mechKeywordCannotBeEmpty();

    @Message(id = 5066, value = "No value found for keyword: %s")
    AuthenticationMechanismException mechNoValueFoundForKeyword(String keyword);

    @Message(id = 5067, value = "'=' expected after keyword: %s")
    AuthenticationMechanismException mechKeywordNotFollowedByEqual(String keyword);

    @Message(id = 5068, value = "Unmatched quote found for value: %s")
    AuthenticationMechanismException mechUnmatchedQuoteFoundForValue(String value);

    @Message(id = 5069, value = "Expecting comma or linear whitespace after quoted string: %s")
    AuthenticationMechanismException mechExpectingCommaOrLinearWhitespaceAfterQuoted(String value);

    @Message(id = 5070, value = "MessageType must equal to %d, but it is %d")
    AuthenticationMechanismException mechMessageTypeMustEqual(int expected, int actual);

    @Message(id = 5071, value = "Bad sequence number while unwrapping: expected %d, but %d received")
    AuthenticationMechanismException mechBadSequenceNumberWhileUnwrapping(int expected, int actual);

    @Message(id = 5072, value = "Problem during crypt")
    AuthenticationMechanismException mechProblemDuringCrypt(@Cause Throwable cause);

    @Message(id = 5073, value = "Problem during decrypt")
    AuthenticationMechanismException mechProblemDuringDecrypt(@Cause Throwable cause);

    @Message(id = 5074, value = "Unknown cipher \"%s\"")
    AuthenticationMechanismException mechUnknownCipher(String cipher);

    @Message(id = 5075, value = "Authorization ID changed unexpectedly")
    AuthenticationMechanismException mechAuthorizationIdChanged();

    @Message(id = 5076, value = "Problem getting required cipher. Check your transformation mapper settings.")
    AuthenticationMechanismException mechProblemGettingRequiredCipher(@Cause Throwable cause);

    @Message(id = 5077, value = "No common protection layer between client and server")
    AuthenticationMechanismException mechNoCommonProtectionLayer();

    @Message(id = 5078, value = "No common cipher between client and server")
    AuthenticationMechanismException mechNoCommonCipher();

    @Message(id = 5079, value = "No ciphers offered by server")
    AuthenticationMechanismException mechNoCiphersOfferedByServer();

    @Message(id = 5080, value = "Callback handler not provided user name")
    AuthenticationMechanismException mechNotProvidedUserName();

    @Message(id = 5083, value = "Missing \"%s\" directive")
    AuthenticationMechanismException mechMissingDirective(String directive);

    @Message(id = 5084, value = "nonce-count must equal to %d, but it is %d")
    AuthenticationMechanismException mechNonceCountMustEqual(int expected, int actual);

    @Message(id = 5085, value = "Server is set to not support %s charset")
    AuthenticationMechanismException mechUnsupportedCharset(String charset);

    @Message(id = 5086, value = "Charset can be only \"utf-8\" or unspecified (to use ISO 8859-1)")
    AuthenticationMechanismException mechUnknownCharset();

    @Message(id = 5087, value = "Client selected realm not offered by server (%s)")
    AuthenticationMechanismException mechDisallowedClientRealm(String clientRealm);

    @Message(id = 5088, value = "digest-uri \"%s\" not accepted")
    AuthenticationMechanismException mechMismatchedWrongDigestUri(String actual);

    @Message(id = 5089, value = "Unexpected qop value: \"%s\"")
    AuthenticationMechanismException mechUnexpectedQop(String qop);

    @Message(id = 5090, value = "Wrapping is not configured")
    IllegalStateException wrappingNotConfigured();

    @Message(id = 5091, value = "Authentication name string is too long")
    AuthenticationMechanismException mechAuthenticationNameTooLong();

    @Message(id = 5092, value = "Authentication name is empty")
    AuthenticationMechanismException mechAuthenticationNameIsEmpty();

    @Message(id = 5093, value = "Authorization for anonymous access is denied")
    AuthenticationMechanismException mechAnonymousAuthorizationDenied();

    @Message(id = 5094, value = "Required padded length (%d) is less than length of conversion result (%d)")
    IllegalArgumentException requiredNegativePadding(int totalLength, int hexLength);

    @Message(id = 5095, value = "Invalid key provided for Digest HMAC computing")
    AuthenticationMechanismException mechInvalidKeyForDigestHMAC();

    @Message(id = 5097, value = "Unable to determine subject name from X.509 certificate")
    IllegalStateException unableToDetermineSubjectName(@Cause Throwable cause);

    @Message(id = 5098, value = "Unable to verify client signature")
    AuthenticationMechanismException mechUnableToVerifyClientSignature(@Cause Throwable cause);

    @Message(id = 5099, value = "Unable to verify server signature")
    AuthenticationMechanismException mechUnableToVerifyServerSignature(@Cause Throwable cause);

    @Message(id = 5101, value = "Callback handler not provided server certificate")
    AuthenticationMechanismException mechCallbackHandlerNotProvidedServerCertificate();

    @Message(id = 5102, value = "Callback handler not provided client certificate")
    AuthenticationMechanismException mechCallbackHandlerNotProvidedClientCertificate();

    @Message(id = 5103, value = "Server identifier mismatch")
    AuthenticationMechanismException mechServerIdentifierMismatch();

    @Message(id = 5104, value = "Client identifier mismatch")
    AuthenticationMechanismException mechClientIdentifierMismatch();

    @Message(id = 5105, value = "Unable to determine client name")
    AuthenticationMechanismException mechUnableToDetermineClientName(@Cause Throwable cause);

    @Message(id = 5106, value = "Callback handler not provided private key")
    AuthenticationMechanismException mechCallbackHandlerNotProvidedPrivateKey();

    @Message(id = 5107, value = "Unable to create signature")
    AuthenticationMechanismException mechUnableToCreateSignature(@Cause Throwable cause);

    @Message(id = 5108, value = "Unable to create response token")
    AuthenticationMechanismException mechUnableToCreateResponseToken(@Cause Throwable cause);

    @Message(id = 5109, value = "Unable to create response token")
    AuthenticationMechanismException mechUnableToCreateResponseTokenWithCause(@Cause Throwable cause);

    @Message(id = 5112, value = "Getting authentication mechanisms supported by GSS-API failed")
    AuthenticationMechanismException mechGettingSupportedMechanismsFailed(@Cause Throwable cause);

    @Message(id = 5113, value = "Unable to initialize OID of Kerberos V5")
    RuntimeException unableToInitialiseOid(@Cause Throwable cause);

    @Message(id = 5114, value = "Receive buffer requested '%d' is greater than supported maximum '%d'")
    AuthenticationMechanismException mechReceiveBufferIsGreaterThanMaximum(int requested, int maximum);

    @Message(id = 5115, value = "Unable to wrap message")
    AuthenticationMechanismException mechUnableToWrapMessage(@Cause Throwable cause);

    @Message(id = 5116, value = "Unable to unwrap message")
    AuthenticationMechanismException mechUnableToUnwrapMessage(@Cause Throwable cause);

    @Message(id = 5117, value = "Unable to unwrap security layer negotiation message")
    AuthenticationMechanismException mechUnableToUnwrapSecurityLayerNegotiationMessage(@Cause Throwable cause);

    @Message(id = 5118, value = "Invalid message of length %d on unwrapping")
    AuthenticationMechanismException mechInvalidMessageOnUnwrapping(int length);

    @Message(id = 5119, value = "Negotiated mechanism was not Kerberos V5")
    AuthenticationMechanismException mechNegotiatedMechanismWasNotKerberosV5();

    @Message(id = 5120, value = "Insufficient levels of protection available for supported security layers")
    AuthenticationMechanismException mechInsufficientQopsAvailable();

    @Message(id = 5121, value = "Unable to generate security layer challenge")
    AuthenticationMechanismException mechUnableToGenerateChallenge(@Cause Throwable cause);

    @Message(id = 5122, value = "Client selected a security layer that was not offered by server")
    AuthenticationMechanismException mechSelectedUnofferedQop();

    @Message(id = 5123, value = "No security layer selected but message length received")
    AuthenticationMechanismException mechNoSecurityLayerButLengthReceived();

    @Message(id = 5124, value = "Unable to get maximum size of message before wrap")
    AuthenticationMechanismException mechUnableToGetMaximumSizeOfMessage(@Cause Throwable cause);

    @Message(id = 5125, value = "Unable to handle response from server")
    AuthenticationMechanismException mechUnableToHandleResponseFromServer(@Cause Throwable cause);

    @Message(id = 5126, value = "Bad length of message for negotiating security layer")
    AuthenticationMechanismException mechBadLengthOfMessageForNegotiatingSecurityLayer();

    @Message(id = 5127, value = "No security layer supported by server but maximum message size received: \"%d\"")
    AuthenticationMechanismException mechReceivedMaxMessageSizeWhenNoSecurityLayer(int length);

    @Message(id = 5128, value = "Failed to read challenge file")
    AuthenticationMechanismException mechFailedToReadChallengeFile(@Cause Throwable cause);

    @Message(id = 5129, value = "Failed to create challenge file")
    AuthenticationMechanismException mechFailedToCreateChallengeFile(@Cause Throwable cause);

    @Message(id = 5150, value = "Authentication mechanism authorization ID is too long")
    AuthenticationMechanismException mechAuthorizationIdTooLong();

    @Message(id = 5151, value = "Invalid OTP algorithm \"%s\"")
    AuthenticationMechanismException mechInvalidOTPAlgorithm(String algorithm);

    @Message(id = 5152, value = "Invalid OTP response type")
    AuthenticationMechanismException mechInvalidOTPResponseType();

    @Message(id = 5153, value = "Incorrect parity in SASL client message")
    AuthenticationMechanismException mechIncorrectParity();

    @Message(id = 5154, value = "Invalid character in seed")
    AuthenticationMechanismException mechInvalidCharacterInSeed();

    @Message(id = 5155, value = "Invalid OTP seed, must be between 1 and 16 characters long")
    AuthenticationMechanismException mechInvalidOTPSeed();

    @Message(id = 5156, value = "Invalid OTP pass phrase, must be between 10 and 63 characters long")
    AuthenticationMechanismException mechInvalidOTPPassPhrase();

    @Message(id = 5157, value = "Invalid OTP sequence number")
    AuthenticationMechanismException mechInvalidOTPSequenceNumber();

    @Message(id = 5158, value = "Invalid OTP")
    AuthenticationMechanismException mechInvalidOTP();

    @Message(id = 5159, value = "OTP pass phrase and seed must not match")
    AuthenticationMechanismException mechOTPPassPhraseAndSeedMustNotMatch();

    @Message(id = 5160, value = "Invalid OTP alternate dictionary")
    AuthenticationMechanismException mechInvalidOTPAlternateDictionary();

    @Message(id = 5161, value = "Unable to retrieve password for \"%s\"")
    AuthenticationMechanismException mechUnableToRetrievePassword(String userName);

    @Message(id = 5162, value = "Unable to update password for \"%s\"")
    AuthenticationMechanismException mechUnableToUpdatePassword(String userName);

    @Message(id = 5163, value = "Authentication mechanism server timed out")
    AuthenticationMechanismException mechServerTimedOut();

    @Message(id = 5164, value = "Unable to obtain exclusive access for \"%s\"")
    AuthenticationMechanismException mechUnableToObtainExclusiveAccess(String userName);

    @Message(id = 5165, value = "OTP re-initialization failed")
    AuthenticationMechanismException mechOTPReinitializationFailed(@Cause Throwable cause);

    @Message(id = 5166, value = "Server rejected authentication")
    ScramServerException scramServerRejectedAuthentication(@Param ScramServerErrorCode errorCode);

    @Message(id = 5167, value = "Invalid OTP password format type")
    AuthenticationMechanismException mechInvalidOTPPasswordFormatType();

    @Message(id = 5168, value = "Unsupported algorithm selected \"%s\"")
    AuthenticationMechanismException mechUnsupportedAlgorithm(String algorithm);

    @Message(id = 5169, value = "[%s] Clients response token does not match expected token")
    String mechResponseTokenMismatch(String mechName);

    @Message(id = 5170, value = "Problem during crypt: The encrypted result is null. The input data has a length of zero or too short to result in a new block.")
    AuthenticationMechanismException mechProblemDuringCryptResultIsNull();

    @Message(id = 5171, value = "Problem during decrypt: The decrypted result is null. The input data has a length of zero or too short to result in a new block.")
    AuthenticationMechanismException mechProblemDuringDecryptResultIsNull();

    @Message(id = 5173, value = "Unable to obtain server credential.")
    AuthenticationMechanismException unableToObtainServerCredential();

    @Message(id = 5174, value = "Callback handler has not chosen realm")
    AuthenticationMechanismException mechNotChosenRealm();

    @Message(id = 5175, value = "Unable to determine bound server name")
    AuthenticationMechanismException mechUnableToDetermineBoundServerName(@Cause Exception e);

    @Message(id = 5176, value = "Unsupported callback")
    AuthenticationMechanismException mechCallbackHandlerUnsupportedCallback(@Cause Throwable cause);

    @Message(id = 5177, value = "One of \"%s\" and \"%s\" directives has to be defined")
    AuthenticationMechanismException mechOneOfDirectivesHasToBeDefined(String directive1, String directive2);

    @Message(id = 6001, value = "An incorrectly formatted '%s'header was encountered.")
    String incorrectlyFormattedHeader(String headerName);

    @Message(id = 6002, value = "An authentication attempt for user '%s' failed validation using mechanism '%s'.")
    String authenticationFailed(String username, String mechanismName);

    @Message(id = 6003, value = "An authentication attempt failed validation.")
    String authenticationFailed();

    @Message(id = 6006, value = "An authorization check for user '%s' failed.")
    String authorizationFailed(String username);

    @Message(id = 6015, value = "Unable to authenticate using DIGEST mechanism - realm name needs to be specified")
    HttpAuthenticationException digestMechanismRequireRealm();

    @Message(id = 6019, value = "Unable to authenticate using DIGEST mechanism - mechanism realm name (%s) is not valid")
    HttpAuthenticationException digestMechanismInvalidRealm(String realm);

    @Message(id = 6020, value = "Scope unsuitable for use with authentication state '%s'")
    IllegalArgumentException unsuitableScope(String scopeName);

    @Message(id = 6021, value = "Unable to identify suitable HttpScope for mechanism state storage")
    IllegalArgumentException unableToIdentifyHttpScope();

    @Message(id = 6022, value = "Invalid nonce count %s")
    HttpAuthenticationException invalidNonceCount(int nonceCount);

    @Message(id = 7001, value = "Unrecognized encoding algorithm [%s]")
    ASN1Exception asnUnrecognisedAlgorithm(String algorithm);

    @Message(id = 7002, value = "Invalid general name type")
    ASN1Exception asnInvalidGeneralNameType();

    @Message(id = 7004, value = "Unexpected ASN.1 tag encountered")
    ASN1Exception asnUnexpectedTag();
}
