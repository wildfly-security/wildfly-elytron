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

package org.wildfly.security.x500._private;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.wildfly.security.asn1.ASN1Exception;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 6, value = "Unexpected trailing garbage in X.500 principal")
    IllegalArgumentException unexpectedTrailingGarbageInX500principal();
    
    @Message(id = 10025, value = "Non-X.509 certificate found in certificate array")
    IllegalArgumentException nonX509CertificateInCertificateArray();
    
    @Message(id = 10026, value = "Starting public key not found in certificate array")
    IllegalArgumentException startingPublicKeyNotFoundInCertificateArray();
    
    @Message(id = 10027, value = "Incomplete certificate array")
    IllegalArgumentException incompleteCertificateArray();
    
    @Message(id = 10028, value = "Unable to create X.509 certificate chain from map of certificates")
    IllegalArgumentException unableToCreateCertificateChainFromCertificateMap();
    
    @Message(id = 5110, value = "Invalid value for trusted authority type; expected a value between 0 and 4 (inclusive)")
    IllegalArgumentException invalidValueForTrustedAuthorityType();
    
    @Message(id = 5111, value = "Invalid value for a general name type; expected a value between 0 and 8 (inclusive)")
    IllegalArgumentException invalidValueForGeneralNameType();
    
    @Message(id = 7006, value = "Invalid general name for URI type")
    ASN1Exception asnInvalidGeneralNameForUriType(@Cause Throwable cause);
    
    @Message(id = 7007, value = "Invalid general name for IP address type")
    ASN1Exception asnInvalidGeneralNameForIpAddressType();
    
    @Message(id = 7008, value = "IP address general name cannot be resolved")
    ASN1Exception asnIpAddressGeneralNameCannotBeResolved(@Cause Throwable cause);
    
    @Message(id = 7025, value = "Invalid general name for URI type: missing scheme")
    ASN1Exception asnInvalidGeneralNameForUriTypeMissingScheme();
    
  
}
