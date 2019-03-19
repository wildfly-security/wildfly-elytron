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

package org.wildfly.security.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidParameterSpecException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;


/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 9, value = "Invalid name \"%s\"")
    IllegalArgumentException generalInvalidName(String str);

    @Message(id = 3025, value = "Iteration count not specified for password based encryption")
    IllegalArgumentException iterationCountNotSpecified();

    @Message(id = 3026, value = "Salt not specified for password based encryption")
    IllegalArgumentException saltNotSpecified();

    @Message(id = 3027, value = "Initial key not specified for password based encryption")
    IllegalArgumentException initialKeyNotSpecified();

    @Message(id = 3028, value = "Security provider \"%s\" doesn't exist")
    IllegalArgumentException securityProviderDoesnExist(String providerName);

    @Message(id = 3029, value = "No such key algorithm \"%s\"")
    IllegalArgumentException noSuchKeyAlgorithm(String algorithmName, @Cause GeneralSecurityException cause);

    @Message(id = 3030, value = "I/O operation failed: closed")
    IOException closed();

    @Message(id = 3032, value = "Base64 string created with unsupported PicketBox version \"%s\"")
    IllegalArgumentException wrongBase64InPBCompatibleMode(String base64);

    @Message(id = 4020, value = "Mechanism \"%s\" not supported by transformation mapper")
    IllegalArgumentException mechanismNotSupported(String mechanism);

    @Message(id = 8030, value = "Failed to encode parameter specification")
    InvalidParameterSpecException failedToEncode(@Cause Throwable cause);

    @Message(id = 8031, value = "Failed to decode parameter specification")
    IOException failedToDecode(@Cause Throwable cause);

    @Message(id = 8032, value = "Invalid parameter specification type (expected %s, got %s)")
    InvalidParameterSpecException invalidParameterSpec(Class<?> expected, Class<?> actual);

    @Message(id = 8033, value = "Invalid format given (expected %s, got %s)")
    IOException invalidFormat(String expected, String actual);

    @Message(id = 8034, value = "Algorithm parameters instance not initialized")
    IllegalStateException algorithmParametersNotInitialized();

}
