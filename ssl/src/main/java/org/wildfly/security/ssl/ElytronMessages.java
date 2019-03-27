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

package org.wildfly.security.ssl;

import static org.jboss.logging.Logger.Level.WARN;

import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;

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
    @ValidIdRange(min = 1066, max = 1077),
    @ValidIdRange(min = 4001, max = 4031),
    @ValidIdRange(min = 5015, max = 5017),
    @ValidIdRange(min = 15000, max = 15999)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages tls = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.tls");

    @LogMessage(level = WARN)
    @Message(id = 1066, value = "Invalid string count for mechanism database entry \"%s\"")
    void warnInvalidStringCountForMechanismDatabaseEntry(String name);

    @LogMessage(level = WARN)
    @Message(id = 1067, value = "Invalid key exchange \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidKeyExchangeForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1068, value = "Invalid authentication \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidAuthenticationForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1069, value = "Invalid encryption \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidEncryptionForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1070, value = "Invalid digest \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidDigestForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1071, value = "Invalid protocol \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidProtocolForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1072, value = "Invalid level \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidLevelForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1073, value = "Invalid strength bits \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidStrengthBitsForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1074, value = "Invalid algorithm bits \"%s\" for mechanism database entry \"%s\"")
    void warnInvalidAlgorithmBitsForMechanismDatabaseEntry(String value, String name);

    @LogMessage(level = WARN)
    @Message(id = 1075, value = "Invalid duplicate mechanism database entry \"%s\"")
    void warnInvalidDuplicateMechanismDatabaseEntry(String name);

    @LogMessage(level = WARN)
    @Message(id = 1076, value = "Invalid duplicate OpenSSL-style alias \"%s\" for mechanism database entry \"%s\" (original is \"%s\")")
    void warnInvalidDuplicateOpenSslStyleAliasForMechanismDatabaseEntry(String alias, String name, String originalName);

    @LogMessage(level = WARN)
    @Message(id = 1077, value = "Invalid alias \"%s\" for missing mechanism database entry \"%s\"")
    void warnInvalidAliasForMissingMechanismDatabaseEntry(String value, String name);

    @Message(id = 4001, value = "No algorithm found matching TLS/SSL protocol selection criteria")
    NoSuchAlgorithmException noAlgorithmForSslProtocol();

    @Message(id = 4002, value = "Empty certificate chain is not trusted")
    CertificateException emptyChainNotTrusted();

    @Message(id = 4003, value = "Certificate not trusted due to realm failure for principal [%s]")
    CertificateException notTrustedRealmProblem(@Cause RealmUnavailableException e, Principal principal);

    @Message(id = 4004, value = "Credential validation failed: certificate is not trusted for principal [%s]")
    CertificateException notTrusted(Principal principal);

    @Message(id = 4005, value = "No default trust manager available")
    NoSuchAlgorithmException noDefaultTrustManager();

    @Message(id = 4006, value = "No context for SSL connection")
    SSLHandshakeException noContextForSslConnection();

    @Message(id = 4007, value = "SSL channel is closed")
    SSLException sslClosed();

    @Message(id = 4008, value = "Initial SSL/TLS data is not a handshake record")
    SSLHandshakeException notHandshakeRecord();

    @Message(id = 4009, value = "Initial SSL/TLS handshake record is invalid")
    SSLHandshakeException invalidHandshakeRecord();

    @Message(id = 4010, value = "Initial SSL/TLS handshake spans multiple records")
    SSLHandshakeException multiRecordSSLHandshake();

    @Message(id = 4011, value = "Expected \"client hello\" record")
    SSLHandshakeException expectedClientHello();

    @Message(id = 4012, value = "Unsupported SSL/TLS record")
    SSLHandshakeException unsupportedSslRecord();

    @Message(id = 4013, value = "Invalid TLS extension data")
    SSLProtocolException invalidTlsExt();

    @Message(id = 4014, value = "Not enough data in record to fill declared item size")
    SSLProtocolException notEnoughData();

    @Message(id = 4015, value = "Empty host name in SNI record data")
    SSLProtocolException emptyHostNameSni();

    @Message(id = 4016, value = "Duplicated SNI server name of type %d")
    SSLProtocolException duplicatedSniServerName(int type);

    @Message(id = 4017, value = "Unknown authentication name \"%s\"")
    IllegalArgumentException unknownAuthenticationName(String name);

    @Message(id = 4018, value = "Unknown encryption name \"%s\"")
    IllegalArgumentException unknownEncryptionName(String name);

    @Message(id = 4019, value = "Unknown key exchange name \"%s\"")
    IllegalArgumentException unknownKeyExchangeName(String name);

    @Message(id = 4024, value = "Invalid client mode, expected %s, got %s")
    IllegalArgumentException invalidClientMode(boolean expectedMode, boolean givenMode);

    @Message(id = 4026, value = "Could not create trust manager [%s]")
    IllegalStateException sslErrorCreatingTrustManager(String name, @Cause Throwable cause);

    @Message(id = 4027, value = "SecurityDomain of SSLContext does not support X509PeerCertificateChainEvidence verification")
    IllegalArgumentException securityDomainOfSSLContextDoesNotSupportX509();

    @Message(id = 4029, value = "Default context cannot be null")
    IllegalStateException defaultContextCannotBeNull();

    @Message(id = 4030, value = "No context for SSL connection")
    SSLException noSNIContextForSslConnection(); // TODO Compare with noContextForSslConnection.

    @Message(id = 4031, value = "TrustManagerFactory algorithm [%s] does not support certificate revocation")
    IllegalStateException sslErrorCreatingRevocationTrustManager(String name, @Cause Throwable cause);

    @Message(id = 5015, value = "Unexpected character U+%04x at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedChar(int codePoint, long offset, String string);

    @Message(id = 5016, value = "Unrecognized token \"%s\" in mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnknownToken(String word, String string);

    @Message(id = 5017, value = "Token \"%s\" not allowed at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenNotAllowed(String token, long offset, String string);

    @Message(id = 15000, value = "Uknown cipher suite name '%s' in names string '%s'")
    IllegalArgumentException unknownCipherSuiteName(String name, String string);

}
