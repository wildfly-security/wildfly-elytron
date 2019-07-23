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

package org.wildfly.security.sasl._private;

import static org.jboss.logging.Logger.Level.WARN;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.mechanism.AuthenticationMechanismException;


/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 1157, max = 1157),
    @ValidIdRange(min = 5001, max = 5163)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages sasl = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl");

    @LogMessage(level = WARN)
    @Message(id = 1157, value = "Unable to resolve MechanismConfiguration for MechanismInformation")
    void unableToResolveMechanismConfiguration(@Cause Throwable e);

    @Message(id = 5001, value = "Authentication mechanism exchange received a message after authentication was already complete")
    AuthenticationMechanismException mechMessageAfterComplete();

    @Message(id = 5005, value = "Authentication mechanism authentication is not yet complete")
    IllegalStateException mechAuthenticationNotComplete();

    @Message(id = 5015, value = "Unexpected character U+%04x at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedChar(int codePoint, long offset, String string);

    @Message(id = 5017, value = "Token \"%s\" not allowed at offset %d of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorTokenNotAllowed(String token, long offset, String string);

    @Message(id = 5020, value = "Unexpected end of mechanism selection string \"%s\"")
    IllegalArgumentException mechSelectorUnexpectedEnd(String string);

    @Message(id = 5058, value = "Authentication failed")
    AuthenticationMechanismException mechAuthenticationFailed();

    @Message(id = 5090, value = "Wrapping is not configured")
    IllegalStateException wrappingNotConfigured();

    @Message(id = 5130, value = "Invalid non-ASCII space \"0x%X\"")
    IllegalArgumentException invalidNonAsciiSpace(int input);

    @Message(id = 5053, value = "Callback handler failed for unknown reason")
    AuthenticationMechanismException mechCallbackHandlerFailedForUnknownReason(@Cause Throwable cause);

    @Message(id = 5131, value = "Invalid ASCII control \"0x%X\"")
    IllegalArgumentException invalidAsciiControl(int input);

    @Message(id = 5132, value = "Invalid non-ASCII control \"0x%X\"")
    IllegalArgumentException invalidNonAsciiControl(int input);

    @Message(id = 5133, value = "Invalid private use character \"0x%X\"")
    IllegalArgumentException invalidPrivateUseCharacter(int input);

    @Message(id = 5134, value = "Invalid non-character code point \"0x%X\"")
    IllegalArgumentException invalidNonCharacterCodePoint(int input);

    @Message(id = 5135, value = "Invalid surrogate code point \"0x%X\"")
    IllegalArgumentException invalidSurrogateCodePoint(int input);

    @Message(id = 5136, value = "Invalid plain text code point \"0x%X\"")
    IllegalArgumentException invalidPlainTextCodePoint(int input);

    @Message(id = 5137, value = "Invalid non-canonical code point \"0x%X\"")
    IllegalArgumentException invalidNonCanonicalCodePoint(int input);

    @Message(id = 5138, value = "Invalid control character \"0x%X\"")
    IllegalArgumentException invalidControlCharacter(int input);

    @Message(id = 5139, value = "Invalid tagging character \"0x%X\"")
    IllegalArgumentException invalidTaggingCharacter(int input);

    @Message(id = 5140, value = "Unassigned code point \"0x%X\"")
    IllegalArgumentException unassignedCodePoint(int input);

    @Message(id = 5141, value = "Invalid surrogate pair (high at end of string) \"0x%X\"")
    IllegalArgumentException invalidSurrogatePairHightAtEnd(char input);

    @Message(id = 5142, value = "Invalid surrogate pair (second is not low) \"0x%X 0x%X\"")
    IllegalArgumentException invalidSurrogatePairSecondIsNotLow(char high, char low);

    @Message(id = 5143, value = "Invalid surrogate pair (low without high) \"0x%X\"")
    IllegalArgumentException invalidSurrogatePairLowWithoutHigh(char low);

    @Message(id = 5144, value = "Invalid code point \"0x%X\"")
    IllegalArgumentException invalidCodePoint(int input);

    @Message(id = 5145, value = "Disallowed R/AL directionality character in L string")
    IllegalArgumentException disallowedRalDirectionalityInL();

    @Message(id = 5146, value = "Disallowed L directionality character in R/AL string")
    IllegalArgumentException disallowedLDirectionalityInRal();

    @Message(id = 5147, value = "Missing trailing R/AL directionality character")
    IllegalArgumentException missingTrailingRal();

    @Message(id = 5148, value = "Invalid escape sequence")
    IllegalArgumentException invalidEscapeSequence();

    @Message(id = 5163, value = "Authentication mechanism server timed out")
    AuthenticationMechanismException mechServerTimedOut();
}
