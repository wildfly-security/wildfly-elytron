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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.cli.MissingArgumentException;
import org.apache.commons.cli.MissingOptionException;
import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
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
    @Message(id = NONE, value = "Command or alias \"%s\" not found.")
    String commandOrAliasNotFound(String command);

    @Message(id = NONE, value = "Input data not confirmed. Exiting.")
    String inputDataNotConfirmed();

    @Message(id = NONE, value = "%s %s")
    String cmdHelp(String toolCommand, String commandName);

    @Message(id = NONE, value = "Exception encountered executing the command:")
    String commandExecuteException();

    // CredentialStore command parameters descriptions
    @Message(id = NONE, value = "Printing general help message:")
    String generalHelpTitle();

    @Message(id = NONE, value = "Location of credential store storage file")
    String cmdLineStoreLocationDesc();

    @Message(id = NONE, value = "\"credential-store\" command is used to perform various operations on credential store.")
    String cmdLineCredentialStoreHelpHeader();

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

    @Message(id = NONE, value = "The alias of the existing password entry to encrypt")
    String cmdLineEntryDesc();

    @Message(id = NONE, value = "Type of entry in credential store")
    String cmdLineEntryTypeDesc();

    @Message(id = NONE, value = "Comma separated list of JCA provider names. Providers will be supplied to the credential store instance.%n" +
            "Each provider must be installed through java.security file or through service loader from properly packaged jar file on classpath.")
    String cmdLineOtherProvidersDesc();

    @Message(id = NONE, value = "Provider name containing CredentialStoreSpi implementation.%n" +
            "Provider must be installed through java.security file or through service loader from properly packaged jar file on classpath.")
    String cmdLineCustomCredentialStoreProviderDesc();

    @Message(id = NONE, value = "Create credential store (Action)")
    String cmdLineCreateCredentialStoreDesc();

    @Message(id = NONE, value = "Credential store type")
    String cmdLineCredentialStoreTypeDesc();

    @Message(id = NONE, value = "Add new alias to the credential store (Action)")
    String cmdLineAddAliasDesc();

    @Message(id = NONE, value = "Remove alias from the credential store (Action)")
    String cmdLineRemoveAliasDesc();

    @Message(id = NONE, value = "Check if alias exists within the credential store (Action)")
    String cmdLineCheckAliasDesc();

    @Message(id = NONE, value = "Display all aliases (Action)")
    String cmdLineAliasesDesc();

    @Message(id = NONE, value = "Display all types of stored credentials for given alias (Action)")
    String cmdLineAliasTypes();

    @Message(id = NONE, value = "Generate private and public key pair and store them as a KeyPairCredential")
    String cmdLineGenerateKeyPairDesc();

    @Message(id = NONE, value = "Size (number of bytes) of the keys when generating a KeyPairCredential.")
    String cmdLineKeySizeDesc();

    @Message(id = NONE, value = "Encryption algorithm to be used when generating a KeyPairCredential: RSA, DSA, or EC. Default RSA")
    String cmdLineKeyAlgorithmDesc();

    @Message(id = NONE, value = "Prints the public key stored under a KeyPairCredential as Base64 encoded String, in OpenSSH format.")
    String cmdLineExportPublicKeyDesc();

    @Message(id = NONE, value = "Import a KeyPairCredential into the credential store.")
    String cmdLineImportKeyPairDesc();

    @Message(id = NONE, value = "The location of a file containing a private key.")
    String cmdLinePrivateKeyLocationDesc();

    @Message(id = NONE, value = "The location of a file containing a public key.")
    String cmdLinePublicKeyLocationDesc();

    @Message(id = NONE, value = "The passphrase used to decrypt the private key.")
    String cmdLineKeyPassphraseDesc();

    @Message(id = NONE, value = "A private key specified as a String.")
    String cmdLinePrivateKeyStringDesc();

    @Message(id = NONE, value = "A public key specified as a String.")
    String cmdLinePublicKeyStringDesc();

    @Message(id = NONE, value = "Print summary, especially command how to create this credential store")
    String cmdLinePrintSummary();

    @Message(id = NONE, value = "Get help with usage of this command (Action)")
    String cmdLineHelp();

    @Message(id = NONE, value = "Alias \"%s\" exists")
    String aliasExists(String alias);

    @Message(id = NONE, value = "Alias \"%s\" does not exist")
    String aliasDoesNotExist(String alias);

    @Message(id = NONE, value = "Alias \"%s\" of type \"%s\" does not exist")
    String aliasDoesNotExist(String alias, String type);

    @Message(id = NONE, value = "Alias \"%s\" has been successfully stored")
    String aliasStored(String alias);

    @Message(id = NONE, value = "Alias \"%s\" of type \"%s\" has been successfully stored")
    String aliasStored(String alias, String type);

    @Message(id = NONE, value = "Alias \"%s\" has been successfully removed")
    String aliasRemoved(String alias);

    @Message(id = NONE, value = "Alias \"%s\" of type \"%s\" has been successfully removed")
    String aliasRemoved(String alias, String type);

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

    @Message(id = NONE, value = "Passphrase to be used to decrypt private key (can be nothing if no passphrase was used to encrypt the key): ")
    String keyPassphrasePrompt();

    @Message(id = NONE, value = "Confirm passphrase to be used to decrypt private key (can be nothing if no passphrase was used to encrypt the key): ")
    String keyPassphrasePromptConfirm();

    @Message(id = NONE, value = "Secret to store: ")
    String secretToStorePrompt();

    @Message(id = NONE, value = "Confirm secret to store: ")
    String secretToStorePromptConfirm();

    @Message(id = NONE, value = "The retrieved PasswordCredential does not contain a ClearTextPassword")
    String passwordCredentialNotClearText();

    // mask command
    @Message(id = NONE, value = "\"mask\" command is used to get MASK- string encrypted using PBEWithMD5AndDES in PicketBox compatible way.")
    String cmdMaskHelpHeader();

    @Message(id = NONE, value = "Salt to apply to masked string")
    String cmdMaskSaltDesc();

    @Message(id = NONE, value = "Iteration count for masked string")
    String cmdMaskIterationCountDesc();

    @Message(id = NONE, value = "Secret to be encrypted")
    String cmdMaskSecretDesc();

    @Message(id = 6, value = "Salt not specified.")
    MissingArgumentException saltNotSpecified();

    @Message(id = 7, value = "Invalid \"%s\" value. Must be an integer between %d and %d, inclusive")
    IllegalArgumentException invalidParameterMustBeIntBetween(String parameter, int min, int max);

    @Message(id = NONE, value = "Secret not specified.")
    MissingArgumentException secretNotSpecified();

    // vault command
    @Message(id = NONE, value = "\"vault\" command is used convert PicketBox Security Vault to credential store using default implementation (KeyStoreCredentialStore)" +
                                " or custom implementation set with the \"type\" option.")
    String cmdVaultHelpHeader();

    @Message(id = NONE, value = "Vault keystore URL (defaults to \"vault.keystore\")")
    String cmdLineVaultKeyStoreURL();

    @Message(id = NONE, value = "Vault keystore password:%n" +
                                "- used to open original vault key store%n" +
                                "- used as password for new converted credential store")
    String cmdLineVaultKeyStorePassword();

    @Message(id = NONE, value = "Vault directory containing encrypted files (defaults to \"vault\")")
    String cmdLineVaultEncryptionDirectory();

    @Message(id = NONE, value = "8 character salt (defaults to \"12345678\")")
    String cmdVaultLineSalt();

    @Message(id = NONE, value = "Iteration count (defaults to \"23\")")
    String cmdLineVaultIterationCount();

    @Message(id = NONE, value = "Vault key alias within key store (defaults to \"vault\")")
    String cmdLineVaultKeyStoreAlias();

    @Message(id = NONE, value = "Configuration parameters for credential store in form of: \"parameter1=value1; ... ;parameterN=valueN\"%n" +
            "Supported parameters are dependent on credential store type%n" +
            "Generally supported parameters for default credential store implementation (all are optional):%n" +
            "create - automatically creates credential store file (true/false)%n" +
            "modifiable - is the credential modifiable (true/false)%n" +
            "location - file location of credential store%n" +
            "keyStoreType - specify the key store type to use")
    String cmdLineVaultCSParametersDesc();

    @Message(id = NONE, value = "Vault Conversion summary:%n--------------------------------------%n%s%n--------------------------------------%n")
    String vaultConversionSummary(String command);

    @Message(id = NONE, value = "Vault Conversion Successful%n")
    String conversionSuccessful();

    @Message(id = NONE, value = "CLI command to add new credential store:%n")
    String cliCommandToNewCredentialStore();

    @Message(id = NONE, value = "Bulk conversion with options listed in description file. All options have no default value and should be set in the file. (Action)%n" +
                                "All options are required with the exceptions:%n" +
                                " - \"properties\" option%n - \"type\" option (defaults to \"KeyStoreCredentialStore\")%n - \"credential-store-provider\" option%n - \"other-providers\" option%n" +
                                " - \"salt\" and \"iteration\" options can be omitted when plain-text password is used%n" +
                                "Each set of options must start with the \"keystore\" option in the following format:%n " +
                                "keystore:<value>%nkeystore-password:<value>%nenc-dir:<value>%nsalt:<value>%niteration:<value>%nlocation:<value>%n" +
                                "alias:<value>%nproperties:<parameter1>=<value1>; ... ;<parameterN>=<valueN>%ntype:<value>%n" +
                                "credential-store-provider:<value>%nother-providers:<value>")
    String cliCommandBulkVaultCredentialStoreConversion();

    @Message(id = NONE, value = "Print summary of conversion")
    String cmdLineVaultPrintSummary();

    @Message(id = NONE, value = "Converted credential store type (defaults to \"KeyStoreCredentialStore\")")
    String cmdLineVaultCSTypeDesc();

    @Message(id = NONE, value = "Location of credential store storage file (defaults to \"converted-vault.cr-store\" in vault encryption directory)")
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

    @Message(id = 16, value = "Option \"%s\" is not specified.")
    MissingArgumentException optionNotSpecified(String option);

    @Message(id = 17, value = "Option \"%s\" specified more than once. Only the first occurrence will be used.")
    String duplicateOptionSpecified(String option);

    @Message(id = 18, value = "Option \"%s\" does not expect any arguments.")
    MissingArgumentException noArgumentOption(String option);

    @Message(id = NONE, value = "Vault password: ")
    String vaultPasswordPrompt();

    @Message(id = 19, value = "Encryption directory \"%s\" does not contain \"VAULT.dat\" file.")
    IllegalArgumentException vaultFileNotFound(String path);

    @Message(id = NONE, value = "Mask secret: ")
    String maskSecretPrompt();

    @Message(id = NONE, value = "Confirm mask secret: ")
    String maskSecretPromptConfirm();

    @Message(id = NONE, value = "Print stack trace when error occurs.")
    String cmdLineDebug();

    @Message(id = NONE, value = "Exception encountered executing the command. Use option \"--debug\" for complete exception stack trace.")
    String commandExecuteExceptionNoDebug();

    @Message(id = 20, value = "Alias was not defined.")
    MissingArgumentException undefinedAlias();

    @Message(id = 21, value = "Location of the output file was not defined.")
    MissingArgumentException undefinedOutputLocation();

    @Message(id = 22, value = "Encryption directory was not defined.")
    MissingArgumentException undefinedEncryptionDirectory();

    @Message(id = 23, value = "Vault password was not defined")
    MissingArgumentException undefinedVaultPassword();

    @Message(id = 24, value = "Cannot parse conversion descriptor file \"%s\". No keystore specified.")
    IOException undefinedKeystore(String file);

    @Message(id = 25, value = "Credential store storage file \"%s\" does not exist.")
    IllegalArgumentException storageFileDoesNotExist(String location);

    @Message(id = 26, value = "Credential store storage file \"%s\" already exists.")
    IllegalArgumentException storageFileExists(String location);

    @Message(id = 27, value = "Wrong masked password format. Expected format is \"MASK-<encoded payload>;<salt>;<iteration>\"")
    IllegalArgumentException wrongMaskedPasswordFormat();

    @Message(id = 28, value = "Location parameter is not specified for filebased keystore type '%s'")
    MissingArgumentException filebasedKeystoreLocationMissing(String type);

    @Message(id = 29, value = "Key Pair Algorithm: '%s' is not supported.")
    NoSuchAlgorithmException unknownKeyPairAlgorithm(String algorithm);

    @Message(id = 30, value = "Key file '%s' does not exist.")
    IllegalArgumentException keyFileDoesNotExist(String location);

    @Message(id = 31, value = "No private key specified for importing.")
    MissingArgumentException noPrivateKeySpecified();

    @Message(id = 32, value = "No public key specified for importing.")
    MissingArgumentException noPublicKeySpecified();

    @Message(id = 33, value = "No PEM content found")
    MissingArgumentException xmlNoPemContent();

    @Message(id = 34, value = "Invalid keysize provided: %s")
    InvalidParameterException invalidKeySize(String reason);

    @Message(id = NONE, value = "In the message below, option '%s' refers to long option '%s'.")
    String longOptionDescription(String option, String longOption);

    // filesystem-realm command
    @Message(id = NONE, value = "'FileSystemRealm' command is used to convert legacy properties files and scripts to an Elytron FileSystemRealm.")
    String cmdFileSystemRealmHelpHeader();

    @Message(id = NONE, value = "The relative or absolute path to the users file.")
    String cmdFileSystemRealmUsersFileDesc();

    @Message(id = NONE, value = "The relative or absolute path to the credential store file that contains the secret key.")
    String cmdFileSystemEncryptCredentialStoreDesc();

    @Message(id = NONE, value = "The alias of the secret key stored in the credential store file. Set to key by default")
    String cmdFileSystemEncryptSecretKeyDesc();

    @Message(id = NONE, value = "Whether or not the credential store should be populated with a Secret Key. Set to true by default.")
    String cmdFileSystemRealmEncryptPopulateDesc();

    @Message(id = NONE, value = "Whether or not the credential store should be dynamically created if it doesn't exist. Set to true by default.")
    String cmdFileSystemEncryptCreateCredentialStoreDesc();

    @Message(id = NONE, value = "Input Realm location not specified.")
    MissingArgumentException inputLocationNotSpecified();

    @Message(id = NONE, value = "Input Realm location directory does not exist.")
    MissingArgumentException inputLocationDoesNotExist();

    @Message(id = NONE, value = "Output Realm location not specified.")
    MissingArgumentException outputLocationNotSpecified();

    @Message(id = NONE, value = "Credential Store location not specified.")
    MissingArgumentException credentialStoreDoesNotExist();

    @Message(id = NONE, value = "A required parameter is not specified.")
    String fileSystemEncryptRequiredParametersNotSpecified();

    @Message(id = NONE, value = "The hash encoding to be used in the filesystem realm. Set to BASE64 by default.")
    String cmdFileSystemEncryptHashEncodingDesc();

    @Message(id = NONE, value = "If the original realm has encoded set to true. Set to true by default.")
    String cmdFileSystemEncryptEncodedDesc();

    @Message(id = NONE, value = "The levels to be used in the filesystem realm. Set to 2 by default.")
    String cmdFileSystemEncryptLevelsDesc();

    @Message(id = NONE, value = "The absolute or relative location of the original filesystem realm.")
    String cmdFileSystemEncryptInputLocationDesc();

    @Message(id = NONE, value = "The directory where the new filesystem realm resides.")
    String cmdFileSystemEncryptOutputLocationDesc();

    @Message(id = NONE, value = "The name of the new filesystem-realm.")
    String cmdFileSystemEncryptNewRealmDesc();

    @Message(id = NONE, value = "The relative or absolute path to the roles file.")
    String cmdFileSystemRealmRolesFileDesc();

    @Message(id = NONE, value = "The relative or absolute path to the output directory.")
    String cmdFileSystemRealmOutputLocationDesc();

    @Message(id = NONE, value = "Name of the filesystem-realm to be configured.")
    String cmdFileSystemRealmFileSystemRealmNameDesc();

    @Message(id = NONE, value = "Name of the security-domain to be configured.")
    String cmdFileSystemRealmSecurityDomainNameDesc();

    @Message(id = NONE, value = "Bulk conversion with options listed in description file. Optional options have default values, required options do not. (Action) %n" +
            "The options fileSystemRealmName and securityDomainName are optional. %n" +
            "These optional options have default values of: converted-properties-filesystem-realm and converted-properties-security-domain. %n" +
            "Values are required for the following options: users-file, roles-file, and output-location. %n" +
            "If one or more these required values are not set, the corresponding block is skipped. %n" +
            "Each option must be specified in the following format: <option>:<value>. The order of options does not matter. %n" +
            "Blocks of options must be separated by a blank line.")
    String cmdFileSystemRealmBulkConvertDesc();

    @Message(id = NONE, value = "Bulk conversion with options listed in description file. Optional options have default values, required options do not. (Action) %n" +
            "The options realm-name, hash-encoding, hash-charset, levels, secret-key, create, populate, keystore, type, password, password-env, and key-pair are optional. %n" +
            "Values are required for the following options: input-location, output-location, and credential-store. %n" +
            "The default values of realm-name, hash-encoding, hash-charset, levels, secret-key, create, and populate are encrypted-filesystem-realm, BASE64, UTF-8, 2, key, true, and true respectively. %n" +
            "If one or more these required values are not set, the corresponding block is skipped. %n" +
            "Each option must be specified in the following format: <option>:<value>. The order of options does not matter. %n" +
            "Blocks of options must be separated by a blank line.")
    String cmdFileSystemRealmEncryptBulkConvertDesc();

    // filesystem-realm encrypt command
    @Message(id = NONE, value = "'FileSystemRealmEncrypt' command is used to convert un-encrypted FileSystemSecurityRealm(s) to encrypted FileSystemSecurityRealm(s) with a SecretKey.")
    String cmdFileSystemEncryptHelpHeader();

    @Message(id = NONE, value = "Secret Key was not found in the Credential Store at %s, and populate option was not set. Skipping descriptor file block number %d.")
    String cmdFileSystemEncryptionNoSecretKey(String credentialStorePath, Integer blockNumber);

    @Message(id = NONE, value = "The character set used to convert the password string to a byte array. Defaults to UTF-8.")
    String cmdFileSystemRealmIntegrityHashCharsetDesc();

    @Message(id = NONE, value = "Suppresses all output except errors and prompts.")
    String cmdFileSystemRealmSilentDesc();

    @Message(id = NONE, value = "Provides a detailed summary of all operations performed, once the command finishes.")
    String cmdFileSystemRealmSummaryDesc();

    @Message(id = NONE, value = "No users file specified. Please use either --bulk-convert <file> or specify a users file using --users-file <file>")
    MissingOptionException missingUsersFile();

    @Message(id = NONE, value = "No roles file specified. Please use either --bulk-convert <file> or specify a roles file using --roles-file <file>")
    MissingOptionException missingRolesFile();

    @Message(id = NONE, value = "No output location specified. Please use either --bulk-convert <file> or specify an output location using --output-location <directory>")
    MissingOptionException missingOutputLocation();

    @Message(id = NONE, value = "Both --bulk-convert and one or more of --users-file, --roles-file, and/or --output-location were specified. Please only use --bulk-convert or all of --users-file, --roles-file, and --output-location.")
    MissingOptionException mutuallyExclusiveOptionsSpecified();

    @Message(id = NONE, value = "Both --bulk-convert and one or more of --old-realm-name, --new-realm-name, --input-location, --output-location, --credential-store, and/or --secret-key were specified. Please only use --bulk-convert or all of the other others.")
    MissingOptionException mutuallyExclusiveOptionsEncryptSpecified();

    @Message(id = NONE, value = "No value found for %s.")
    String noValueFound(String param);

    @Message(id = NONE, value = "Could not find the specified file %s.")
    FileNotFoundException fileNotFound(String file);

    @Message(id = NONE, value = "Skipping descriptor file block number %d due to %s.")
    String skippingDescriptorBlock(Integer blockNumber, String reason);

    @Message(id = NONE, value = "Skipping descriptor file block number %d due to missing input realm location.")
    String skippingDescriptorBlockInputLocation(Integer blockNumber);

    @Message(id = NONE, value = "Skipping descriptor file block number %d due to missing credential store location.")
    String skippingDescriptorBlockCredentialStoreLocation(Integer blockNumber);


    @Message(id = NONE, value = "Skipping descriptor file block number %d due to missing output realm location.")
    String skippingDescriptorBlockOutputLocation(Integer blockNumber);

    @Message(id = NONE, value = "Skipping descriptor file block number %d due to missing new filesystem realm name.")
    String skippingDescriptorBlockFilesystemRealmName(Integer blockNumber);

    @Message(id = NONE, value = "Creating encrypted realm for: %s")
    String fileSystemRealmEncryptCreatingRealm(String realmName);

    @Message(id = NONE, value = "Should file %s be overwritten? (y/n) ")
    String shouldFileBeOverwritten(String file);

    @Message(id = NONE, value = "\nSome of the parameters below are mutually exclusive actions which are marked with (Action) in the description.")
    String cmdLineActionsHelpHeader();

    @Message(id = NONE, value = "Key size (bits).")
    String keySize();

    @Message(id = NONE, value = "Generate a new SecretKey and store it in the credential store.")
    String generateSecretKey();

    @Message(id = NONE, value = "Export existing SecretKey stored in the credential store.")
    String exportSecretKey();

    @Message(id = NONE, value = "Exported SecretKey for alias %s=%s")
    String exportedSecretKey(String alias, String key);

    @Message(id = NONE, value = "The encoded Key to import.")
    String key();

    @Message(id = NONE, value = "Import an existing encoded SecretKey to the credential store.")
    String importSecretKey();

    @Message(id = NONE, value = "SecretKey to import: ")
    String keyToImport();

    @Message(id = NONE, value = "Encrypt a clear text string using the SecretKey specified by <alias>.")
    String encrypt();

    @Message(id = NONE, value = "The clear text to encrypt.")
    String clearText();

    @Message(id = NONE, value = "Clear text value:")
    String clearTextToImport();

    @Message(id = NONE, value = "Confirm clear text value:")
    String clearTextToImportAgain();

    @Message(id = NONE, value = "Clear text encrypted to token '%s' using alias '%s'.")
    String encryptedToken(String token, String alias);

    @Message(id = NONE, value = "Location that has been specified '%s' does not exist and automatic storage creation for the Credential Store is disabled.")
    IllegalArgumentException locationDoesNotExistCreationDisabled(String location);

    @Message(id = NONE, value = "Credential store contains credentials of types:%s for alias '%s'")
    String types(String types, String alias);

    @Message(id = NONE, value = "Invalid \"%s\" parameter. Default value \"%s\" will be used.")
    String invalidParameterDefaultWillBeUsed(String parameter, String value);

    @Message(id = NONE, value = "Invalid \"%s\" parameter. Generated value \"%s\" will be used.")
    String invalidParameterGeneratedWillBeUsed(String parameter, String value);

    @Message(id = NONE, value = "Mask password operation is not allowed in FIPS mode.")
    String fipsModeNotAllowed();

    @Message(id = NONE, value = "Found credential store and alias, using pre-existing key")
    String existingCredentialStore();

    @Message(id = NONE, value = "Skipping descriptor file block number %d due to failure to load Credential Store.")
    String skippingDescriptorBlockCredentialStoreNotLoaded(Integer blockNumber);

    @Message(id = NONE, value = "Credential Store at %s does not support SecretKey. Skipping descriptor file block number %d.")
    String skippingDescriptorBlockSecretKeyUnsupported(String credentialStorePath, Integer blockNumber);

    @Message(id = NONE, value = "Exception was thrown while populating Credential Store at %s. Skipping descriptor file block number %d.")
    String skippingDescriptorBlockUnableToPopulateCredentialStore(String credentialStorePath, Integer blockNumber);

    @Message(id = NONE, value = "No Credential Store location or Secret Key Alias specified.")
    MissingOptionException missingCredentialStoreSecretKey();

    // Numeric Errors
    @Message(id = 35, value = "Only one of '%s' and '%s' can be specified at the same time")
    IllegalArgumentException mutuallyExclusiveOptions(String first, String second);

}
