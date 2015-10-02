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

package org.wildfly.security._private;

import static org.jboss.logging.Logger.Level.WARN;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @LogMessage
    @Message(id = 1, value = "WildFly Elytron version %s")
    void logVersion(String versionString);

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

    @Message(id = 4017, value = "Unknown authentication name \"%s\"")
    IllegalArgumentException unknownAuthenticationName(String name);

    @Message(id = 4018, value = "Unknown encryption name \"%s\"")
    IllegalArgumentException unknownEncryptionName(String name);

    @Message(id = 4019, value = "Unknown key exchange name \"%s\"")
    IllegalArgumentException unknownKeyExchangeName(String name);

    @Message(id = 5015, value = "Unexpected character U+%04x at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedChar(int codePoint, int offset, String string);

    @Message(id = 5016, value = "Unrecognized token \"%s\" in mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnknownToken(String word, String string);

    @Message(id = 5017, value = "Token \"%s\" not allowed at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenNotAllowed(String token, int offset, String string);

}
