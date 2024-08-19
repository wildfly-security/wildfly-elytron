/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.encryption;

import java.security.GeneralSecurityException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;

/**
 * Log messages and exceptions for the 'encryption' module.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 19000, max = 19999)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 19000, value = "Invalid size value. Must be one of 128, 192, or 256")
    GeneralSecurityException badKeySize();

    @Message(id = 19001, value = "Invalid prefix importing SecretKey")
    GeneralSecurityException badKeyPrefix();

    @Message(id = 19002, value = "Unsupported version '%d' the maximum supported version is '%d'")
    GeneralSecurityException unsupportedVersion(int discovered, int maxSupported);

    @Message(id = 19003, value = "Unexpected token type '%s', expected '%s'")
    GeneralSecurityException unexpectedTokenType(String actual, String expected);

    @Message(id = 19004, value = "Unable to decode Base64 token.")
    GeneralSecurityException unableToDecodeBase64Token(@Cause Throwable cause);

}
