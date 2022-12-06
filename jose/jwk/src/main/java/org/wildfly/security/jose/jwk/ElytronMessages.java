/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.jose.jwk;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
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
        @ValidIdRange(min = 24000, max = 24999)
})
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.jose.jwk");

    @Message(id = 24000, value = "Unable to parse string JWK")
    IllegalArgumentException unableToParseStringJWK(@Cause Exception cause);

    @Message(id = 24001, value = "Unsupported key type for JWK: \"%s\"")
    IllegalArgumentException unsupportedKeyTypeForJWK(String keyType);

    @Message(id = 24002, value = "Unsupported curve")
    IllegalArgumentException unsupportedCurve();

    @Message(id = 24003, value = "Unable to create public key from JWK")
    RuntimeException unableToCreatePublicKeyFromJWK(@Cause Exception cause);

    @Message(id = 24004, value = "Unable to generate thumbprint for the certificate")
    RuntimeException unableToGenerateThumbprint(@Cause Exception cause);
}
