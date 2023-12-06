/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.encryption.client._private;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Param;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;

import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.security.encryption.client.EncryptedExpressionResolutionException;

import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamReader;

/**
 * Log messages and exceptions for Encryption Client.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

@MessageLogger(projectCode = "ELY", length = 5)
@ValidIdRanges({
        @ValidIdRange(min = 1001, max = 1002),
        @ValidIdRange(min = 1028, max = 1029),
        @ValidIdRange(min = 1035, max = 1036),
        @ValidIdRange(min = 1041, max = 1041),
        @ValidIdRange(min = 1064, max = 1064),
        @ValidIdRange(min = 1091, max = 1091),
        @ValidIdRange(min = 1129, max = 1144),
        @ValidIdRange(min = 1159, max = 1159),
        @ValidIdRange(min = 1162, max = 1164),
        @ValidIdRange(min = 1166, max = 1166),
        @ValidIdRange(min = 2034, max = 2034),
        @ValidIdRange(min = 2010, max = 2010),
        @ValidIdRange(min = 4005, max = 4005),
        @ValidIdRange(min = 4028, max = 4028),
        @ValidIdRange(min = 9501, max = 9503),
        @ValidIdRange(min = 9527, max = 9527),
        @ValidIdRange(min = 9529, max = 9529),
        @ValidIdRange(min = 14000, max = 14999)
})
public interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");
    ElytronMessages xmlLog = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.xml");

    @Message(id = 14009, value = "The expression '%s' does not specify a resolver and no default is defined.")
    EncryptedExpressionResolutionException expressionResolutionWithoutResolver(String expression);

    @Message(id = 14010, value = "The expression '%s' specifies a resolver configuration which does not exist.")
    EncryptedExpressionResolutionException invalidResolver(String expression);

    @Message(id = 14011, value = "Unable to load credential from credential store.")
    EncryptedExpressionResolutionException unableToLoadCredential(@Cause Throwable cause);

    @Message(id = 14012, value = "Unable to decrypt expression '%s'.")
    EncryptedExpressionResolutionException unableToDecryptExpression(String expression, @Cause Throwable cause);

    @Message(id = 14013, value = "The name of the resolver to use was not specified and no default-resolver has been defined.")
    EncryptedExpressionResolutionException noResolverSpecifiedAndNoDefault();

    @Message(id = 14014, value = "No expression resolver has been defined with the name '%s'.")
    EncryptedExpressionResolutionException noResolverWithSpecifiedName(String name);

    @Message(id = 14015, value = "Credential alias '%s' of credential type '%s' does not exist in the store")
    EncryptedExpressionResolutionException credentialDoesNotExist(String alias, String credentialType);

    @Message(id = 14016, value = "Unable to encrypt the supplied clear text.")
    EncryptedExpressionResolutionException unableToEncryptClearText(@Cause Throwable cause);

    @Message(id = 14017, value = "Duplicate attribute (\"%s\") found in configuration.")
    ConfigXMLParseException duplicateAttributeFound(@Param XMLStreamReader reader, String attribute);

    @Message(id = 14018, value = "Failed to create credential")
    ConfigXMLParseException xmlFailedToCreateCredential(@Param Location location, @Cause Throwable cause);

    @Message(id = 14019, value = "No module found for identifier \"%s\"")
    ConfigXMLParseException xmlNoModuleFound(@Param XMLStreamReader reader, @Cause Exception e,
                                             String moduleIdentifier);

    @Message(id = 14020, value = "Duplicate credential store name found in configuration \"%s\"")
    ConfigXMLParseException duplicateCredentialStoreName(@Param XMLStreamReader reader, String storeName);

    @Message(id = 14021, value = "The expression to decrypt cannot be null.")
    EncryptedExpressionResolutionException expressionUnavailable();
}