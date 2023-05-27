/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.client.utils;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.http.client.exception.ElytronHttpClientException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
        @ValidIdRange(min = 41000, max = 41999)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 41000, value = "Name callback handling unsuccessful.")
    ElytronHttpClientException nameCallBackHandlingFailed();

    @Message(id = 41001, value = "Password callback handling unsuccessful.")
    ElytronHttpClientException passwordCallBackHandlingFailed();

    @Message(id = 41002, value = "Response Header Extraction Failed.")
    ElytronHttpClientException responseHeaderExtractionFailed();

    @Message(id = 41003, value = "Credential Callback Handling Unsuccessful.")
    ElytronHttpClientException credentialCallbackHandlingFailed();

    @Message(id = 41004, value = "Provided Algorithm Not Available.")
    ElytronHttpClientException digestAuthenticationAlgorithmNotAvailable();

}
