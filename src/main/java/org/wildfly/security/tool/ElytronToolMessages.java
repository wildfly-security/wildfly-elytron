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

import static org.jboss.logging.annotations.Message.NONE;

import org.apache.commons.cli.MissingArgumentException;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

import java.io.IOException;

/**
 * Messages for Elytron tool.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
@MessageLogger(projectCode = "ELYTOOL", length = 5)
public interface ElytronToolMessages extends BasicLogger {

    ElytronToolMessages msg = Logger.getMessageLogger(ElytronToolMessages.class, "org.wildfly.security.tool");

    // General messages
    @Message(id = NONE, value = "Command or alias \"%s\" not found.")
    String commandOrAliasNotFound(String command);

    @Message(id = NONE, value = "Input data not confirmed. Exiting.")
    String inputDataNotConfirmed();

    @Message(id = NONE, value = "java -jar %s %s")
    String cmdHelp(String jarFile, String commandName);

    @Message(id = NONE, value = "Exception encountered executing the command:")
    String commandExecuteException();

    // CredentialStore command parameters descriptions
    @Message(id = NONE, value = "Missing arguments. Printing general help message:")
    String missingArgumentsHelp();

    @Message(id = NONE, value = "Location of credential store storage file")
    String cmdLineStoreLocationDesc();

    @Message(id = NONE, value = "Implementation properties for credential store type in form of \"prop1=value1; ... ;propN=valueN\" .%n" +
            "Supported properties are dependent on credential store type%n" +
            "KeyStoreCredentialStore (default implementation) supports following additional properties (all are optional):%n" +
            "keyStoreType - specifies the key store type to use (defaults to \"JCEKS\")%n" +
            "keyAlias - specifies the secret key alias within the key store to use for encrypt/decrypt of data in external storage (defaults to \"cs_key\")%n" +
            "external - specifies whether to store data to external storage and encrypted by keyAlias key (defaults to \"false\")%n" +
            "cryptoAlg - cryptographic algorithm name to be used to encrypt/decrypt entries at external storage \"external\" has to be set to \"true\"")
    String cmdLineImplementationPropertiesDesc();

    @Message(id = NONE, value = "Password for credential store")
    String cmdLineCredentialStorePassword();

    @Message(id = NONE, value = "Salt to apply for final masked password of the credential store")
    String cmdLineSaltDesc();

    @Message(id = NONE, value = "Iteration count for final masked password of the credential store")
    String cmdLineIterationCountDesc();

    @Message(id = NONE, value = "Password credential value")
    String cmdLinePasswordCredentialValueDesc();

    @Message(id = NONE, value = "Type of entry in credential store")
    String cmdLineEntryTypeDesc();

    @Message(id = NONE, value = "Comma separated list of JCA provider names. Providers will be supplied to the credential store instance.%n" +
            "Each provider must be installed through java.security file.")
    String cmdLineOtherProvidersDesc();

    @Message(id = NONE, value = "Create credential store [true/false]")
    String cmdLineCreateCredentialStoreDesc();

    @Message(id = NONE, value = "Credential store type")
    String cmdLineCredentialStoreTypeDesc();

    @Message(id = NONE, value = "Add new alias to the credential store")
    String cmdLineAddAliasDesc();

    @Message(id = NONE, value = "Remove alias from the credential store")
    String cmdLineRemoveAliasDesc();

    @Message(id = NONE, value = "Check if alias exists within the credential store")
    String cmdLineCheckAliasDesc();

    @Message(id = NONE, value = "Display all aliases")
    String cmdLineAliasesDesc();

    @Message(id = NONE, value = "Print summary, especially command how to create this credential store")
    String cmdLinePrintSummary();

    @Message(id = NONE, value = "Get help with usage of this command")
    String cmdLineHelp();

    @Message(id = NONE, value = "Alias \"%s\" exists")
    String aliasExists(String alias);

    @Message(id = NONE, value = "Alias \"%s\" does not exist")
    String aliasDoesNotExist(String alias);

    @Message(id = NONE, value = "Alias \"%s\" has been successfully stored")
    String aliasStored(String alias);

    @Message(id = NONE, value = "Alias \"%s\" has been successfully removed")
    String aliasRemoved(String alias);

    @Message(id = NONE, value = "Credential store command summary:%n--------------------------------------%n%s")
    String commandSummary(String command);

    @Message(id = NONE, value = "Credential store contains following aliases: %s")
    String aliases(String aliases);

    @Message(id = NONE, value = "Credential store contains no aliases")
    String noAliases();

    @Message(id = NONE, value = "Action to perform on the credential store is not defined")
    Exception actionToPerformNotDefined();

    @Message(id = NONE, value = "Credential store password: ")
    String credentialStorePasswordPrompt();

    @Message(id = NONE, value = "Confirm credential store password: ")
    String credentialStorePasswordPromptConfirm();

    @Message(id = NONE, value = "Secret to store: ")
    String secretToStorePrompt();

    @Message(id = NONE, value = "Confirm secret to store: ")
    String secretToStorePromptConfirm();

    // mask command
    @Message(id = NONE, value = "\"mask\" command is used to get MASK- string encrypted using PBEWithMD5AndDES in PicketBox compatible way.")
    String cmdMaskHelpHeader();

    @Message(id = NONE, value = "Salt to apply to masked string")
    String cmdMaskSaltDesc();

    @Message(id = NONE, value = "Iteration count for masked string")
    String cmdMaskIterationCountDesc();

    @Message(id = NONE, value = "Secret to be encrypted")
    String cmdMaskSecretDesc();

    @Message(id = 5, value = "Nothing to encrypt. Secret not specified.")
    MissingArgumentException secretNotSpecified();

    @Message(id = 6, value = "Salt not specified.")
    MissingArgumentException saltNotSpecified();

    @Message(id = 7, value = "Invalid \"%s\" value. Must be an integer between %d and %d, inclusive")
    IllegalArgumentException invalidParameterMustBeIntBetween(String parameter, int min, int max);

    // vault command
    @Message(id = NONE, value = "Vault keystore URL")
    String cmdLineVaultKeyStoreURL();

    @Message(id = NONE, value = "Vault keystore password:%n" +
                                "- used to open original vault key store%n" +
                                "- used as password for new converted credential store")
    String cmdLineVaultKeyStorePassword();

    @Message(id = NONE, value = "Vault directory containing encrypted files")
    String cmdLineVaultEncryptionDirectory();

    @Message(id = NONE, value = "8 character salt")
    String cmdVaultLineSalt();

    @Message(id = NONE, value = "Iteration count")
    String cmdLineVaultIterationCount();

    @Message(id = NONE, value = "Vault master key alias within key store")
    String cmdLineVaultKeyStoreAlias();

    @Message(id = NONE, value = "Configuration parameters for credential store in form of: \"parameter1=value1; ... ;parameterN=valueN\"%n" +
            "Supported parameters are dependent on credential store type%n" +
            "Generally supported parameters for default credential store implementation (all are optional):%n" +
            "create - automatically creates credential store file (true/false)%n" +
            "modifiable - is the credential modifiable (true/false)%n" +
            "location - file location of credential store%n" +
            "keyStoreType - specify the key store type to use")
    String cmdLineVaultCSParametersDesc();

    @Message(id = NONE, value = "Vault Conversion summary:%n--------------------------------------%n%s")
    String vaultConversionSummary(String command);

    @Message(id = NONE, value = "Vault Conversion Successful%n")
    String conversionSuccessful();

    @Message(id = NONE, value = "CLI command to add new credential store:%n")
    String cliCommandToNewCredentialStore();

    @Message(id = NONE, value = "Bulk conversion with parameters in description file")
    String cliCommandBulkVaultCredentialStoreConversion();

    @Message(id = NONE, value = "Print summary of conversion")
    String cmdLineVaultPrintSummary();

    @Message(id = NONE, value = "Location of credential store storage file")
    String cmdLineVaultCSLocationDesc();

    @Message(id = 8, value = "Cannot locate admin key with alias \"%s\" or it is of improper type")
    RuntimeException cannotLocateAdminKey(String alias);

    @Message(id = 9, value = "Cannot parse credential store implementation properties from supplied parameter")
    RuntimeException cannotParseProps();

    @Message(id = NONE, value = "Vault (enc-dir=\"%s\";keystore=\"%s\") converted to credential store \"%s\"")
    String vaultConvertedToCS(String vaultDir, String keyStore, String credentialStoreStorage);

    @Message(id = 10, value = "Cannot parse conversion descriptor file \"%s\" missing colon at line %s")
    IOException descriptorParseMissingColon(String file, String line);

    @Message(id = 11, value = "Unrecognized descriptor attribute at line %s")
    IOException unrecognizedDescriptorAttribute(String line);

    @Message(id = 12, value = "Problem converting vault (enc-dir=\"%s\";keystore=\"%s\")")
    Exception bulkConversionProblem(String vaultDir, String keyStore, @Cause Throwable cause);

    @Message(id = 13, value = "Invalid option \"%s\" when performing bulk conversion. Use bulk conversion descriptor file.")
    Exception bulkConversionInvalidOption(String option);

    @Message(id = 14, value = "Unknown entry-type \"%s\"")
    IllegalArgumentException unknownEntryType(String entryType);

    @Message(id = 15, value = "Unknown provider \"%s\"")
    IllegalArgumentException unknownProvider(String provider);

    @Message(id = NONE, value = "Credential Store has been successfully created")
    String credentialStoreCreated();
}
