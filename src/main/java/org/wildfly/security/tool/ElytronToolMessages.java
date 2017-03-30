/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool;

import org.apache.commons.cli.MissingArgumentException;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

/**
 * Messages for Elytron tool.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
@MessageLogger(projectCode = "ELYTOOL", length = 5)
public interface ElytronToolMessages extends BasicLogger {

    ElytronToolMessages msg = Logger.getMessageLogger(ElytronToolMessages.class, "org.wildfly.security.tool");

    // General messages
    @Message(id = Message.NONE, value = "Command or alias \"%s\" not found.")
    String commandOrAliasNotFound(String command);

    @Message(id = Message.NONE, value = "Input data not confirmed. Exiting.")
    String inputDataNotConfirmed();

    @Message(id = Message.NONE, value = "Cannot start user prompt, console is missing.")
    String cannotPromptConsoleMissing();

    @Message(id = Message.NONE, value = "java -jar %s %s")
    String cmdHelp(String jarFile, String commandName);

    // CredentialStore command parameters descriptions
    @Message(id = Message.NONE, value = "Missing arguments. Printing general help message:")
    String missingArgumentsHelp();

    @Message(id = Message.NONE, value = "Location of credential store storage file")
    String cmdLineStoreLocationDesc();

    @Message(id = Message.NONE, value = "Configuration URI for credential store. URI basic form: \"cr-store://store_name?parameter1=value1; ... ;parameterN=valueN\"%n" +
            "Supported parameters are dependent on credential store type%n" +
            "Generally supported parameters for default credential store implementation (all are optional):%n" +
            "create - automatically creates credential store file (true/false)%n" +
            "modifiable - is the credential modifiable (true/false)%n" +
            "location - file location of credential store%n" +
            "keyStoreType - specify the key store type to use")
    String cmdLineURIDesc();

    @Message(id = Message.NONE, value = "Password for credential store")
    String cmdLineCredentialStorePassword();

    @Message(id = Message.NONE, value = "Salt to apply for final masked password of the credential store")
    String cmdLineSaltDesc();

    @Message(id = Message.NONE, value = "Iteration count for final masked password of the credential store")
    String cmdLineIterationCountDesc();

    @Message(id = Message.NONE, value = "Password credential value")
    String cmdLinePasswordCredentialValueDesc();

    @Message(id = Message.NONE, value = "Create credential store [true/false]")
    String cmdLineCreateCredentialStoreDesc();

    @Message(id = Message.NONE, value = "Credential store type")
    String cmdLineCredentialStoreTypeDesc();

    @Message(id = Message.NONE, value = "Add new alias to the credential store")
    String cmdLineAddAliasDesc();

    @Message(id = Message.NONE, value = "Remove alias from the credential store")
    String cmdLineRemoveAliasDesc();

    @Message(id = Message.NONE, value = "Check if alias exists within the credential store")
    String cmdLineCheckAliasDesc();

    @Message(id = Message.NONE, value = "Display all aliases")
    String cmdLineAliasesDesc();

    @Message(id = Message.NONE, value = "Print summary, especially command how to create this credential store")
    String cmdLinePrintSummary();

    @Message(id = Message.NONE, value = "Get help with usage of this command")
    String cmdLineHelp();

    @Message(id = Message.NONE, value = "Alias \"%s\" exists")
    String aliasExists(String alias);

    @Message(id = Message.NONE, value = "Alias \"%s\" does not exist")
    String aliasDoesNotExist(String alias);

    @Message(id = Message.NONE, value = "Alias \"%s\" has been successfully stored")
    String aliasStored(String alias);

    @Message(id = Message.NONE, value = "Alias \"%s\" has been successfully removed")
    String aliasRemoved(String alias);

    @Message(id = Message.NONE, value = "Credential store command summary:%n--------------------------------------%n%s")
    String commandSummary(String command);

    @Message(id = Message.NONE, value = "Credential store contains following aliases: %s")
    String aliases(String aliases);

    @Message(id = Message.NONE, value = "Action to perform on the credential store is not defined")
    Exception actionToPerformNotDefined();

    @Message(id = Message.NONE, value = "Credential store password: ")
    String credentialStorePasswordPrompt();

    @Message(id = Message.NONE, value = "Confirm credential store password: ")
    String credentialStorePasswordPromptConfirm();

    @Message(id = Message.NONE, value = "Secret to store: ")
    String secretToStorePrompt();

    @Message(id = Message.NONE, value = "Confirm secret to store: ")
    String secretToStorePromptConfirm();

    @Message(id = 1, value = "Opening quote has to be the first character in parameter value '%s'")
    IllegalArgumentException credentialStoreURIParameterOpeningQuote(String uri);

    @Message(id = 2, value = "Closing quote has to be the last character of parameter value '%s'")
    IllegalArgumentException credentialStoreURIParameterClosingQuote(String uri);

    @Message(id = 3, value = "Unexpected end of parameter part of '%s'")
    IllegalArgumentException credentialStoreURIParameterUnexpectedEnd(String uri);

    @Message(id = 4, value = "Parameter name expected, but is missing '%s'")
    IllegalArgumentException credentialStoreURIParameterNameExpected(String uri);

    // mask command
    @Message(id = Message.NONE, value = "\"mask\" command is used to get MASK- string encrypted using %s in PicketBox compatible way.")
    String cmdMaskHelpHeader(String algorithm);

    @Message(id = Message.NONE, value = "Salt to apply to masked string")
    String cmdMaskSaltDesc();

    @Message(id = Message.NONE, value = "Iteration count for masked string")
    String cmdMaskIterationCountDesc();

    @Message(id = Message.NONE, value = "Secret to be encrypted")
    String cmdMaskSecretDesc();

    @Message(id = 5, value = "Nothing to encrypt. Secret not specified.")
    MissingArgumentException secretNotSpecified();

}
