/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.ssh.util._pivate;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
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
@MessageLogger(projectCode = "ELY", length = 3)
@ValidIdRanges({
        @ValidIdRange(min = 40000, max = 40999)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 40000, value = "Malformed OpenSSH Private Key: %s")
    IllegalArgumentException openSshParseError(String e);

    @Message(id = 40001, value = "Unable to Generate Key: %s")
    IllegalArgumentException openSshGeneratingError(String e);

    @Message(id = 40002, value = "Malformed PEM content when parsing SSH at offset %d")
    IllegalArgumentException malformedSshPemContent(long offset);
}
