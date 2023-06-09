/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2021 Red Hat, Inc. and/or its affiliates.
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

import static org.wildfly.security.tool.Params.BOOLEAN_PARAM;
import static org.wildfly.security.tool.Params.BULK_CONVERT_PARAM;
import static org.wildfly.security.tool.Params.CREATE_CREDENTIAL_STORE_PARAM;
import static org.wildfly.security.tool.Params.CREDENTIAL_STORE_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.DEBUG_PARAM;
import static org.wildfly.security.tool.Params.DEFAULT_KEY_PAIR_ALIAS;
import static org.wildfly.security.tool.Params.DEFAULT_LEVELS;
import static org.wildfly.security.tool.Params.DEFAULT_SECRET_KEY_ALIAS;
import static org.wildfly.security.tool.Params.DIRECTORY_PARAM;
import static org.wildfly.security.tool.Params.ENCODED_PARAM;
import static org.wildfly.security.tool.Params.FILE_PARAM;
import static org.wildfly.security.tool.Params.HASH_CHARSET_PARAM;
import static org.wildfly.security.tool.Params.HASH_ENCODING_PARAM;
import static org.wildfly.security.tool.Params.HELP_PARAM;
import static org.wildfly.security.tool.Params.INPUT_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.KEYSTORE_PARAM;
import static org.wildfly.security.tool.Params.KEYSTORE_TYPE_PARAM;
import static org.wildfly.security.tool.Params.KEY_PAIR_ALIAS_PARAM;
import static org.wildfly.security.tool.Params.LEVELS_PARAM;
import static org.wildfly.security.tool.Params.LINE_SEPARATOR;
import static org.wildfly.security.tool.Params.NAME_PARAM;
import static org.wildfly.security.tool.Params.OUTPUT_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.OVERWRITE_SCRIPT_FILE;
import static org.wildfly.security.tool.Params.PASSWORD_ENV_PARAM;
import static org.wildfly.security.tool.Params.PASSWORD_PARAM;
import static org.wildfly.security.tool.Params.REALM_NAME_PARAM;
import static org.wildfly.security.tool.Params.SECRET_KEY_ALIAS_PARAM;
import static org.wildfly.security.tool.Params.SILENT_PARAM;
import static org.wildfly.security.tool.Params.SUMMARY_DIVIDER;
import static org.wildfly.security.tool.Params.SUMMARY_PARAM;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.wildfly.security.auth.realm.FileSystemRealmUtil;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.realm.FileSystemSecurityRealmBuilder;
import org.wildfly.security.password.spec.Encoding;

/**
 * Elytron-Tool command to convert un-encrypted FileSystemRealms into an encrypted realm with the use of a SecretKey.
 * Also, optionally provides a WildFly CLI script to register the FileSystemRealm and corresponding
 * security-domain in WildFly.
 *
 * @author <a href="mailto:araskar@redhat.com">Ashpan Raskar</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */

class FileSystemEncryptRealmCommand extends Command {
    static final String FILE_SYSTEM_ENCRYPT_COMMAND = "filesystem-realm-encrypt";

    private static final String POPULATE_SECRET_KEY_PARAM = "populate";
    private static final String DEFAULT_FILESYSTEM_REALM_NAME = "encrypted-filesystem-realm";

    private final List<Descriptor> descriptors = new ArrayList<>();
    private final List<String> PARAMS_LIST = new ArrayList<>(Arrays.asList(INPUT_LOCATION_PARAM, OUTPUT_LOCATION_PARAM));

    private final Options options;
    private final CommandLineParser parser = new DefaultParser();
    private CommandLine cmdLine = null;
    private boolean silentMode = false;
    private boolean summaryMode = false;
    private StringBuilder summaryString = null;
    private boolean warningOccurred = false;

    FileSystemEncryptRealmCommand() {
        options = new Options();
        Option option;

        option = new Option("i", INPUT_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptInputLocationDesc());
        option.setArgName(DIRECTORY_PARAM);
        options.addOption(option);

        option = new Option("r", REALM_NAME_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptNewRealmDesc());
        option.setArgName(DIRECTORY_PARAM);
        options.addOption(option);

        option = new Option("o", OUTPUT_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptOutputLocationDesc());
        option.setArgName(DIRECTORY_PARAM);
        options.addOption(option);

        option = new Option("c", CREDENTIAL_STORE_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptCredentialStoreDesc());
        option.setArgName(FILE_PARAM);
        options.addOption(option);

        option = new Option("a", CREATE_CREDENTIAL_STORE_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptCreateCredentialStoreDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        option = new Option("s", SECRET_KEY_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptSecretKeyDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        options.addOption(Option.builder("k").longOpt(KEYSTORE_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemEncryptKeyStoreDesc())
                .hasArg().argName(FILE_PARAM)
                .build());
        options.addOption(Option.builder("t").longOpt(KEYSTORE_TYPE_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemEncryptKeyStoreTypeDesc())
                .hasArg().argName(NAME_PARAM)
                .build());

        // Password by terminal or environment variable, optional
        options.addOptionGroup(new OptionGroup()
                .addOption(Option.builder().longOpt(PASSWORD_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemEncryptKeyStorePassword())
                        .hasArg().argName(PASSWORD_PARAM)
                        .build())
                .addOption(Option.builder().longOpt(PASSWORD_ENV_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemEncryptKeyStorePasswordEnv())
                        .hasArg().argName(NAME_PARAM)
                        .build())
        );

        options.addOption(Option.builder("y").longOpt(KEY_PAIR_ALIAS_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemEncryptKeyPairAliasDesc())
                .hasArg().argName(NAME_PARAM)
                .build());

        option = new Option("e", HASH_ENCODING_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptHashEncodingDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        option = new Option("u", HASH_CHARSET_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmIntegrityHashCharsetDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        option = new Option("f", ENCODED_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptEncodedDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        option = new Option("l", LEVELS_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptLevelsDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        option = new Option("p", POPULATE_SECRET_KEY_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmEncryptPopulateDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        option = new Option("b", BULK_CONVERT_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmEncryptBulkConvertDesc());
        option.setArgName(FILE_PARAM);
        options.addOption(option);

        option = new Option("w", OVERWRITE_SCRIPT_FILE, true, ElytronToolMessages.msg.cmdFileSystemRealmOverwriteCliScriptFileDesc());
        option.setArgName(BOOLEAN_PARAM);
        options.addOption(option);

        option = Option.builder().longOpt(HELP_PARAM).desc(ElytronToolMessages.msg.cmdLineHelp()).build();
        options.addOption(option);

        option = Option.builder().longOpt(DEBUG_PARAM).desc(ElytronToolMessages.msg.cmdLineDebug()).build();
        options.addOption(option);

        option = Option.builder().longOpt(SILENT_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmSilentDesc()).build();
        options.addOption(option);

        option = Option.builder().longOpt(SUMMARY_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmSummaryDesc()).build();
        options.addOption(option);
    }

    private static final class Descriptor {
        private String inputRealmLocation;
        private String outputRealmLocation;
        private String fileSystemRealmName;
        private String credentialStore;
        private String secretKeyAlias;

        private String keyStoreLocation;
        private String keyStoreType;
        private char[] password;
        private String passwordEnv;
        private String keyPairAlias;

        private Integer levels;
        private Encoding hashEncoding;
        private Charset hashCharset;
        private Boolean encoded;
        private Boolean createCredentialStore;
        private Boolean populate;
        private Boolean overwriteScriptFile;
        Descriptor() {
        }

        Descriptor(Descriptor descriptor) {
            this.inputRealmLocation = descriptor.inputRealmLocation;
            this.outputRealmLocation = descriptor.outputRealmLocation;
            this.fileSystemRealmName = descriptor.fileSystemRealmName;
            this.credentialStore = descriptor.credentialStore;

            this.keyStoreLocation = descriptor.keyStoreLocation;
            this.keyStoreType = descriptor.keyStoreType;
            this.password = descriptor.password;
            this.passwordEnv = descriptor.passwordEnv;
            this.keyPairAlias = descriptor.keyPairAlias;

            this.hashEncoding = descriptor.hashEncoding;
            this.levels = descriptor.levels;
            this.encoded = descriptor.encoded;
            this.hashCharset = descriptor.hashCharset;
            this.createCredentialStore = descriptor.createCredentialStore;
            this.secretKeyAlias = descriptor.secretKeyAlias;
            this.populate = descriptor.populate;
            this.overwriteScriptFile = descriptor.overwriteScriptFile;
        }

        public Encoding getHashEncoding() {
            return hashEncoding;
        }

        public void setHashEncoding(Encoding hashEncoding) {
            this.hashEncoding = hashEncoding;
        }

        public Charset getHashCharset() {
            return hashCharset;
        }

        public void setHashCharset(Charset hashCharset) {
            this.hashCharset = hashCharset;
        }

        public Integer getLevels() {
            return levels;
        }

        public void setLevels(Integer levels) {
            this.levels = levels;
        }

        public String getInputRealmLocation() {
            return inputRealmLocation;
        }

        public void setInputRealmLocation(String inputRealmLocation) {
            this.inputRealmLocation = inputRealmLocation;
        }

        public String getOutputRealmLocation() {
            return outputRealmLocation;
        }

        public void setOutputRealmLocation(String outputRealmLocation) {
            this.outputRealmLocation = outputRealmLocation;
        }

        public String getFileSystemRealmName() {
            return fileSystemRealmName;
        }

        public void setFileSystemRealmName(String fileSystemRealmName) {
            this.fileSystemRealmName = fileSystemRealmName;
        }

        public Boolean getEncoded() {
            return encoded;
        }

        public void setEncoded(boolean encoded) {
            this.encoded = encoded;
        }

        String getCredentialStore() {
            return this.credentialStore;
        }

        void setCredentialStore(String credentialStore) {
            this.credentialStore = credentialStore;
        }

        Boolean getCreateCredentialStore() {
            return this.createCredentialStore;
        }

        void setCreateCredentialStore(Boolean createCredentialStore) {
            this.createCredentialStore = createCredentialStore;
        }

        String getSecretKeyAlias() {
            return this.secretKeyAlias;
        }

        void setSecretKeyAlias(String secretKeyAlias) {
            this.secretKeyAlias = secretKeyAlias;
        }

        Boolean getPopulate() {
            return this.populate;
        }

        void setPopulate(Boolean populate) {
            this.populate = populate;
        }

        String getKeyStoreLocation() {
            return this.keyStoreLocation;
        }

        void setKeyStoreLocation(String keyStoreLocation) {
            this.keyStoreLocation = keyStoreLocation;
        }

        String getKeyStoreType() {
            return this.keyStoreType;
        }

        void setKeyStoreType(String keyStoreType) {
            this.keyStoreType = keyStoreType;
        }

        char[] getPassword() {
            return this.password;
        }

        void setPassword(String password) {
            if (password != null) {
                this.password = password.toCharArray();
            }
        }

        String getPasswordEnv() {
            return this.passwordEnv;
        }

        void setPasswordEnv(String passwordEnv) {
            this.passwordEnv = passwordEnv;
        }

        String getKeyPairAlias() {
            return this.keyPairAlias;
        }

        void setKeyPairAlias(String keyPairAlias) {
            this.keyPairAlias = keyPairAlias;
        }

        public Boolean getOverwriteScriptFile() {
            return overwriteScriptFile;
        }

        public void setOverwriteScriptFile(Boolean overwriteScriptFile) {
            this.overwriteScriptFile = overwriteScriptFile;
        }

        void reset() {
            this.inputRealmLocation = null;
            this.outputRealmLocation = null;
            this.fileSystemRealmName = null;
            this.credentialStore = null;
            this.createCredentialStore = null;
            this.secretKeyAlias = null;
            this.keyStoreLocation = null;
            this.keyStoreType = null;
            this.password = null;
            this.passwordEnv = null;
            this.keyPairAlias = null;
            this.hashEncoding = null;
            this.hashCharset = null;
            this.encoded = null;
            this.levels = null;
            this.populate = null;
            this.overwriteScriptFile = null;
        }
    }

    @Override
    public void execute(String[] args) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        cmdLine = parser.parse(options, args, false);
        setEnableDebug(cmdLine.hasOption(DEBUG_PARAM));
        if (cmdLine.hasOption(HELP_PARAM)) {
            help();
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            return;
        }
        if (cmdLine.hasOption(SILENT_PARAM)) {
            silentMode = true;
        }
        if (cmdLine.hasOption(SUMMARY_PARAM)) {
            summaryMode = true;
            summaryString = new StringBuilder();
            summaryString.append(SUMMARY_DIVIDER);
            summaryString.append(LINE_SEPARATOR);
            summaryString.append("Summary for execution of Elytron-Tool command FileSystemRealmEncrypt");
            summaryString.append(LINE_SEPARATOR);
            summaryString.append(SUMMARY_DIVIDER);
            summaryString.append(LINE_SEPARATOR);
        }
        printDuplicatesWarning(cmdLine);

        String realmNameOption = cmdLine.getOptionValue("r");
        String inputRealmLocationOption = cmdLine.getOptionValue("i");
        String outputRealmLocationOption = cmdLine.getOptionValue("o");
        String credentialStoreOption = cmdLine.getOptionValue("c");
        String createCredentialStore = cmdLine.getOptionValue("a");
        String secretKeyAliasOption = cmdLine.getOptionValue("s");
        String keyStoreLocationOption = cmdLine.getOptionValue("k");
        String keyStoreTypeOption = cmdLine.getOptionValue("t");
        String passwordOption = cmdLine.getOptionValue(PASSWORD_PARAM);
        String passwordEnvOption = cmdLine.getOptionValue(PASSWORD_ENV_PARAM);
        String keyPairAliasOption = cmdLine.getOptionValue("y");
        String hashEncodingOption = cmdLine.getOptionValue("e");
        String hashCharsetOption = cmdLine.getOptionValue("u");
        String levelsOption = cmdLine.getOptionValue("l");
        String encodedOption = cmdLine.getOptionValue("f");
        String bulkConvert = cmdLine.getOptionValue("b");
        String populateOption = cmdLine.getOptionValue("p");
        String overwriteScriptFileOption = cmdLine.getOptionValue("w");

        if (bulkConvert == null) {
            if (realmNameOption == null) {
                realmNameOption = DEFAULT_FILESYSTEM_REALM_NAME;
            }

            Descriptor descriptor = new Descriptor();
            descriptor.setFileSystemRealmName(realmNameOption);
            if (outputRealmLocationOption == null) {
                errorHandler(ElytronToolMessages.msg.outputLocationNotSpecified());
            } else {
                File outputPath = new File(outputRealmLocationOption);
                if (!outputPath.exists()){
                    outputPath.mkdirs();
                }
                descriptor.setOutputRealmLocation(Paths.get(outputRealmLocationOption).toString());
            }
            if (inputRealmLocationOption == null) {
                errorHandler(ElytronToolMessages.msg.inputLocationNotSpecified());
            } else {
                Path inputPath = Paths.get(inputRealmLocationOption);
                descriptor.setInputRealmLocation(inputPath.toString());
                if(Files.notExists(inputPath)) {
                    errorHandler(ElytronToolMessages.msg.inputLocationDoesNotExist());
                }
            }
            if (hashEncodingOption == null) {
                descriptor.setHashEncoding(Encoding.BASE64);
            } else {
                try {
                    descriptor.setHashEncoding(Encoding.valueOf(hashEncodingOption.toUpperCase()));
                } catch (IllegalArgumentException | NullPointerException e) {
                    errorHandler(e);
                }
            }
            if (hashCharsetOption == null) {
                descriptor.setHashCharset(StandardCharsets.UTF_8);
            } else {
                try {
                    descriptor.setHashCharset(Charset.forName(hashCharsetOption.toUpperCase()));
                } catch (IllegalArgumentException e) {
                    errorHandler(e);
                }
            }
            if (populateOption == null) {
                descriptor.setPopulate(true);
            } else {
                descriptor.setPopulate(Boolean.valueOf(populateOption));
            }
            if (overwriteScriptFileOption != null) {
                descriptor.setOverwriteScriptFile(Boolean.valueOf(overwriteScriptFileOption));
            }

            if (levelsOption == null) {
                descriptor.setLevels(DEFAULT_LEVELS);
            } else {
                try {
                    descriptor.setLevels(Integer.parseInt(levelsOption));
                } catch (NumberFormatException e) {
                    errorHandler(e);
                }
            }
            if (encodedOption == null) {
                descriptor.setEncoded(true);
            } else {
                try {
                    descriptor.setEncoded(Boolean.parseBoolean(encodedOption));
                } catch (IllegalArgumentException e) {
                    errorHandler(e);
                }
            }
            if (createCredentialStore != null) {
                descriptor.setCreateCredentialStore(Boolean.valueOf(createCredentialStore));
            } else {
                descriptor.setCreateCredentialStore(true);
            }

            if (credentialStoreOption != null) {
                descriptor.setCredentialStore(credentialStoreOption);
            } else {
                errorHandler(ElytronToolMessages.msg.credentialStoreDoesNotExist());
            }

            if (secretKeyAliasOption != null) {
                descriptor.setSecretKeyAlias(secretKeyAliasOption);
            } else {
                descriptor.setSecretKeyAlias(DEFAULT_SECRET_KEY_ALIAS);
            }

            if (keyStoreLocationOption != null) {
                if (Files.notExists(Paths.get(keyStoreLocationOption))) {
                    throw ElytronToolMessages.msg.keyStoreDoesNotExist();
                }
                descriptor.setKeyStoreLocation(keyStoreLocationOption);
            }
            descriptor.setKeyStoreType(keyStoreTypeOption);

            // Request password if key store provided without password option
            if (keyStoreLocationOption != null) {
                if (passwordOption == null && passwordEnvOption == null) {
                    passwordOption = prompt(false, ElytronToolMessages.msg.keyStorePasswordPrompt(), false, null);
                    if (passwordOption == null) {
                        throw ElytronToolMessages.msg.optionNotSpecified(PASSWORD_PARAM + " or " + PASSWORD_ENV_PARAM);
                    }
                } else if (passwordEnvOption != null) { // Retrieve environment variable
                        descriptor.setPasswordEnv(passwordEnvOption);
                        passwordOption = System.getenv(passwordEnvOption);
                }

                if (keyPairAliasOption != null) {
                    descriptor.setKeyPairAlias(keyPairAliasOption);
                } else {
                    descriptor.setKeyPairAlias(DEFAULT_KEY_PAIR_ALIAS);
                }
            }
            descriptor.setPassword(passwordOption);


            descriptors.add(descriptor);
            checkDescriptorFields(descriptor);
        } else if (inputRealmLocationOption != null || outputRealmLocationOption != null || secretKeyAliasOption != null ||
                realmNameOption != null || credentialStoreOption != null || createCredentialStore != null ||
                keyStoreLocationOption != null || keyStoreTypeOption != null || keyPairAliasOption != null ||
                passwordOption != null || passwordEnvOption != null || hashEncodingOption != null || hashCharsetOption != null ||
                encodedOption != null || levelsOption != null || populateOption != null) {
            throw ElytronToolMessages.msg.mutuallyExclusiveOptionsEncryptSpecified();
        } else {
            if (summaryMode) {
                summaryString.append(String.format("Options were specified via descriptor file: %s, converting multiple old filesystem realm", bulkConvert));
                summaryString.append(LINE_SEPARATOR);
            }
            parseDescriptorFile(bulkConvert);
        }

        createFileSystemRealm();
        createWildFlyScript();

        if (summaryMode) {
            summaryString.append(SUMMARY_DIVIDER);
            summaryString.append(LINE_SEPARATOR);
            summaryString.append("End of summary");
            summaryString.append(LINE_SEPARATOR);
            summaryString.append(SUMMARY_DIVIDER);
            System.out.println(summaryString);
        }

        if (warningOccurred) {
            setStatus(GENERAL_CONFIGURATION_WARNING);
        } else {
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        }
    }

    /**
     * Displays the help for the command
     */
    @Override
    public void help() {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(WIDTH);
        help.printHelp(ElytronToolMessages.msg.cmdHelp(getToolCommand(), FILE_SYSTEM_ENCRYPT_COMMAND),
                ElytronToolMessages.msg.cmdFileSystemEncryptHelpHeader(),
                options,
                "",
                true);
    }

    /**
     * Prints out a warning message if silentMode is not enabled and adds the warning to the summary
     * if summaryMode is enabled
     *
     * @param warning The warning to be shown
     */
    @Override
    protected void warningHandler(String warning) {
        warningOccurred = true;
        if (!silentMode) {
            System.out.print("WARNING: ");
            System.out.println(warning);
        }
        if (summaryMode) {
            summaryString.append("WARNING: ");
            summaryString.append(warning);
            summaryString.append(LINE_SEPARATOR);
        }
    }

    /**
     * Determines if a summary needs to be printed and prints summary after an error is thrown
     *
     * @param e The exception thrown during execution
     * @throws Exception The exception to be handled by Elytron Tool
     */
    @Override
    protected void errorHandler(Exception e) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        if (summaryMode) {
            summaryString.append("Error was thrown during execution:");
            summaryString.append(LINE_SEPARATOR);
            summaryString.append(e.getMessage());
            System.out.println(LINE_SEPARATOR + summaryString.toString());
        }
        throw e;
    }

    /**
     * Prints out information found in a descriptor file for summary mode
     *
     * @param count The amount of descriptor blocks in the file
     */
    private void printDescriptorBlocks(int count) {
        summaryString.append(LINE_SEPARATOR);
        summaryString.append(LINE_SEPARATOR);
        summaryString.append("Found following unencrypted filesystem-realm combinations, null indicates missing required component:");
        summaryString.append(LINE_SEPARATOR);
        for (int i = 0; i < count; i++) {
            StringBuilder summary = new StringBuilder();
            summary.append("\tPrinting summary for block ");
            summary.append(i + 1);
            summary.append(LINE_SEPARATOR);
            Descriptor descriptor = descriptors.get(i);
            for (String param : PARAMS_LIST) {
                summary.append("\t\t");
                summary.append(param);
                summary.append(" - ");
                summary.append(getDescriptorParam(param, descriptor));
                summary.append(LINE_SEPARATOR);
            }
            summaryString.append(summary);
        }
        summaryString.append(LINE_SEPARATOR);
    }

    /**
     * Returns the value for a given param in a Descriptor object
     *
     * @param param      The parameter to be obtained from the Descriptor object
     * @param descriptor The Descriptor object to be used
     * @return The value of the given parameter
     */
    private String getDescriptorParam(String param, Descriptor descriptor) {
        switch (param) {
            case INPUT_LOCATION_PARAM:
                return descriptor.getInputRealmLocation();
            case OUTPUT_LOCATION_PARAM:
                return descriptor.getOutputRealmLocation();
            case REALM_NAME_PARAM:
                return descriptor.getFileSystemRealmName();
            case CREDENTIAL_STORE_LOCATION_PARAM:
                return descriptor.getCredentialStore();
            case SECRET_KEY_ALIAS_PARAM:
                return descriptor.getSecretKeyAlias();
            default:
                return null;
        }
    }

    /**
     * Handles input being given as a descriptor file
     *
     * @throws Exception Exception to be handled by Elytron Tool
     */
    private void parseDescriptorFile(String file) throws Exception {
        Path path = Paths.get(file);
        if (!path.toFile().exists()) {
            errorHandler(ElytronToolMessages.msg.fileNotFound(file));
        }

        Descriptor descriptor = new Descriptor();
        AtomicInteger count = new AtomicInteger(1);
        try (Stream<String> stream = Files.lines(path)) {
            stream.forEach(line -> {
                if (line.equals("")) {
                    if (descriptor.getPasswordEnv() != null) {
                        descriptor.setPassword(System.getenv(descriptor.getPasswordEnv()));
                    }
                    findMissingRequiredValuesAndSetValues(count.intValue(), descriptor);
                    copyAddResetDescriptor(descriptor);
                    count.getAndIncrement();
                } else {
                    String[] parts = line.split(":");
                    String option = parts[0];
                    String arg = parts[1];
                    switch (option) {
                        case INPUT_LOCATION_PARAM:
                            descriptor.setInputRealmLocation(arg);
                            break;
                        case OUTPUT_LOCATION_PARAM:
                            descriptor.setOutputRealmLocation(arg);
                            break;
                        case REALM_NAME_PARAM:
                            descriptor.setFileSystemRealmName(arg);
                            break;
                        case CREDENTIAL_STORE_LOCATION_PARAM:
                            descriptor.setCredentialStore(arg);
                            break;
                        case SECRET_KEY_ALIAS_PARAM:
                            descriptor.setSecretKeyAlias(arg);
                            break;
                        case CREATE_CREDENTIAL_STORE_PARAM:
                            descriptor.setCreateCredentialStore(Boolean.parseBoolean(arg));
                            break;
                        case KEYSTORE_PARAM:
                            descriptor.setKeyStoreLocation(arg);
                            break;
                        case KEYSTORE_TYPE_PARAM:
                            descriptor.setKeyStoreType(arg);
                            break;
                        case PASSWORD_PARAM:
                            descriptor.setPassword(arg);
                            break;
                        case PASSWORD_ENV_PARAM:
                            descriptor.setPasswordEnv(arg);
                            break;
                        case KEY_PAIR_ALIAS_PARAM:
                            descriptor.setKeyPairAlias(arg);
                            break;
                        case HASH_ENCODING_PARAM:
                            descriptor.setHashEncoding(Encoding.valueOf(arg.toUpperCase()));
                            break;
                        case HASH_CHARSET_PARAM:
                            descriptor.setHashCharset(Charset.forName(arg.toUpperCase()));
                            break;
                        case ENCODED_PARAM:
                            descriptor.setEncoded(Boolean.parseBoolean(arg));
                            break;
                        case LEVELS_PARAM:
                            descriptor.setLevels(Integer.parseInt(arg));
                            break;
                        case POPULATE_SECRET_KEY_PARAM:
                            descriptor.setPopulate(Boolean.parseBoolean(arg));
                    }
                }
            });
        } catch (IOException e) {
            errorHandler(e);
        }
        int currentCount = count.intValue();
        findMissingRequiredValuesAndSetValues(currentCount, descriptor);
        copyAddResetDescriptor(descriptor);
        if (summaryMode) {
            printDescriptorBlocks(currentCount);
        }
        count.getAndIncrement();
    }

    /**
     * Copies a Descriptor into a temporary one for it can be cloned into the list of descriptors
     *
     * @param original The original descriptor that is continually modified
     */
    private void copyAddResetDescriptor(Descriptor original) {
        Descriptor temp = new Descriptor(original);
        descriptors.add(temp);
        original.reset();
    }

    /**
     * Determines if the current descriptor block is missing any required values
     * and then if it is, prints out a warning message and sets that required value
     * and the optional values to null
     *
     * @param count The index of the current descriptor block
     */
    private void findMissingRequiredValuesAndSetValues(int count, Descriptor descriptor) {
        boolean missingRequiredValue = false;
        if (descriptor.getInputRealmLocation() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockInputLocation(count));
            missingRequiredValue = true;
        }
        if (descriptor.getOutputRealmLocation() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockOutputLocation(count));
            missingRequiredValue = true;
        }
        if (descriptor.getFileSystemRealmName() == null) {
            descriptor.setFileSystemRealmName(DEFAULT_FILESYSTEM_REALM_NAME + "-" + UUID.randomUUID());
        }
        if(descriptor.getHashEncoding() == null) {
            descriptor.setHashEncoding(Encoding.BASE64);
        }
        if(descriptor.getHashCharset() == null) {
            descriptor.setHashCharset(StandardCharsets.UTF_8);
        }
        if(descriptor.getEncoded() == null) {
            descriptor.setEncoded(true);
        }
        if(descriptor.getLevels() == null) {
            descriptor.setLevels(DEFAULT_LEVELS);
        }
        if(descriptor.getCredentialStore() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockCredentialStoreLocation(count));
            missingRequiredValue = true;
        }
        if(descriptor.getCreateCredentialStore() == null) {
            descriptor.setCreateCredentialStore(true);
        }

        if(descriptor.getPopulate() == null) {
            descriptor.setPopulate(true);
        }

        if(descriptor.getSecretKeyAlias() == null) {
            descriptor.setSecretKeyAlias(DEFAULT_SECRET_KEY_ALIAS);
        }

        if (descriptor.getKeyStoreLocation() != null && descriptor.getPassword() == null && descriptor.getPasswordEnv() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockPassword(count));
            missingRequiredValue = true;
        }

        if (descriptor.getKeyStoreLocation() != null && descriptor.getKeyPairAlias() == null) {
            descriptor.setKeyPairAlias(DEFAULT_KEY_PAIR_ALIAS);
        }

        if (missingRequiredValue) {
            descriptor.reset();
        }
    }

    /**
     * Handles creating the Elytron filesystem-realm from the descriptor array
     *
     * @throws Exception Exception to be handled by Elytron Tool
     */

    private void createFileSystemRealm() throws Exception {
        int blockCount = 0;
        for (Descriptor descriptor : descriptors) {
            blockCount++;
            System.out.println(ElytronToolMessages.msg.fileSystemRealmEncryptCreatingRealm(descriptor.getInputRealmLocation()));
            if (checkDescriptorFields(descriptor)) {
                descriptor.reset();
                continue;
            }

            // Load secret key
            SecretKey key = getSecretKey(descriptor.getCreateCredentialStore(), descriptor.getCredentialStore(),
                    descriptor.getSecretKeyAlias(), descriptor.getPopulate(), blockCount);
            if (key == null)  {
                descriptor.reset();
                continue;
            }

            FileSystemSecurityRealmBuilder oldFileSystemRealmBuilder = FileSystemSecurityRealm.builder()
                    .setRoot(Paths.get(descriptor.getInputRealmLocation()))
                    .setLevels(descriptor.getLevels())
                    .setHashEncoding(descriptor.getHashEncoding())
                    .setHashCharset(descriptor.getHashCharset())
                    .setEncoded(descriptor.getEncoded())
                    .setProviders(ELYTRON_KS_PASS_PROVIDERS);

            FileSystemSecurityRealmBuilder newFileSystemRealmBuilder = FileSystemSecurityRealm.builder()
                    .setRoot(Paths.get(descriptor.getOutputRealmLocation(), descriptor.getFileSystemRealmName()))
                    .setSecretKey(key)
                    .setLevels(descriptor.getLevels())
                    .setProviders(ELYTRON_KS_PASS_PROVIDERS)
                    .setHashCharset(descriptor.getHashCharset());

            // Load integrity KeyPair if provided
            if (descriptor.getKeyStoreLocation() != null) {
                KeyPair keyPair = getKeyPair(Paths.get(descriptor.getKeyStoreLocation()), descriptor.getKeyStoreType(), descriptor.getKeyPairAlias(),
                        descriptor.getPassword(), blockCount);
                if (keyPair != null) {
                    oldFileSystemRealmBuilder.setPublicKey(keyPair.getPublic())
                            .setPrivateKey(keyPair.getPrivate());
                    newFileSystemRealmBuilder.setPublicKey(keyPair.getPublic())
                            .setPrivateKey(keyPair.getPrivate());
                } else {
                    descriptor.reset();
                    continue;
                }
            }

            FileSystemSecurityRealm oldRealm = oldFileSystemRealmBuilder.build();
            if (!oldRealm.getRealmIdentityIterator().hasNext()) {
                warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockEmptyRealm(blockCount));
                descriptor.reset();
                continue;
            }

            FileSystemRealmUtil.cloneIdentitiesToNewRealm(
                    oldRealm,
                    newFileSystemRealmBuilder.build());
        }
    }

    /**
     * Creates the script/commands the user must run for Elytron to recognize
     * and use the new filesystem-realm
     */

    private void createWildFlyScript() throws Exception {
        int counter = 0;
        for (Descriptor descriptor : descriptors) {
            if (checkDescriptorFields(descriptor)) continue;
            String outputRealmLocation = descriptor.getOutputRealmLocation();
            String fileSystemRealmName = descriptor.getFileSystemRealmName();
            String credentialStore = descriptor.getCredentialStore();
            String secretKeyAlias = descriptor.getSecretKeyAlias();
            int levels = descriptor.getLevels();
            Charset hashCharset = descriptor.getHashCharset();
            String keyStoreLocation = descriptor.getKeyStoreLocation();
            String keyStoreType = descriptor.getKeyStoreType();
            char[] password = descriptor.getPassword();
            String keyPairAlias = descriptor.getKeyPairAlias();
            Boolean overwriteScript = descriptor.getOverwriteScriptFile();

            if (hashCharset == null) {
                hashCharset = StandardCharsets.UTF_8;
            }
            if(secretKeyAlias == null) {
                secretKeyAlias = DEFAULT_SECRET_KEY_ALIAS;
            }
            if (keyStoreLocation != null && keyPairAlias == null) {
                keyPairAlias = DEFAULT_KEY_PAIR_ALIAS;
            }
            String createScriptCheck = "";

            Path scriptPath = Paths.get(String.format("%s/%s.cli", outputRealmLocation, fileSystemRealmName));

            if (overwriteScript == null) {
                if (scriptPath.toFile().exists()) {
                    createScriptCheck = prompt(
                            true,
                            ElytronToolMessages.msg.shouldFileBeOverwritten(scriptPath.toString()),
                            false,
                            null
                    );
                    if (createScriptCheck.trim().isEmpty()) createScriptCheck = "n";
                }

                overwriteScript = createScriptCheck.isEmpty() || createScriptCheck.toLowerCase().startsWith("y");
            }

            if (!overwriteScript) { // Generate a random file for the CLI script
                do {
                    scriptPath = Paths.get(String.format("%s/%s.cli",
                            outputRealmLocation,
                            fileSystemRealmName + "-" + UUID.randomUUID()));
                } while (scriptPath.toFile().exists());
            }

            String fullOutputPath;
            if (outputRealmLocation.startsWith(".")) {
                fullOutputPath = Paths.get(outputRealmLocation.substring(2)).toAbsolutePath().toString();
            } else {
                fullOutputPath = Paths.get(outputRealmLocation).toAbsolutePath().toString();
            }

            if (summaryMode) {
                summaryString.append(String.format("Configured script for WildFly at %s", scriptPath));
                summaryString.append(LINE_SEPARATOR);
                summaryString.append("The script is using the following names:");
                summaryString.append(LINE_SEPARATOR);
                summaryString.append(String.format("Name of filesystem-realm: %s", fileSystemRealmName));
                summaryString.append(LINE_SEPARATOR);
            }

            ArrayList<String> scriptLines = new ArrayList<>(Arrays.asList(
                String.format("/subsystem=elytron/secret-key-credential-store=%s:add(path=%s)",
                        "mycredstore"+counter,
                        credentialStore),
                String.format("/subsystem=elytron/filesystem-realm=%s:add(path=%s, levels=%s, credential-store=%s, secret-key=%s%s%s%s%s)",
                        fileSystemRealmName,
                        fullOutputPath+'/'+fileSystemRealmName,
                        levels,
                        "mycredstore"+counter,
                        secretKeyAlias,
                        hashCharset != StandardCharsets.UTF_8 ? ", hash-charset="+hashCharset.name() : "",
                        keyStoreLocation != null ? ", key-store="+"mykeystore"+counter : "",
                        keyPairAlias != null ? ", key-store-alias="+keyPairAlias : "",
                        password != null ? ", credential-reference={clear-text="+Arrays.toString(password)+"}" : ""
                        )
            ));

            if (keyStoreLocation != null) {
                scriptLines.add(1, String.format("/subsystem=elytron/key-store=%s:add(path=%s, credential-reference={clear-text=%s}%s)",
                        "mykeystore"+counter,
                        keyStoreLocation,
                        Arrays.toString(password),
                        keyStoreType != null ? ", type="+keyStoreType : "")
                );
            }

            if (overwriteScript) { // Create a new script file, or overwrite the existing one
                Files.write(scriptPath, scriptLines, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            } else {
                Files.write(scriptPath, scriptLines, StandardOpenOption.CREATE);
            }
            counter++;
        }
    }

    private boolean checkDescriptorFields(Descriptor descriptor) {
        if (descriptor.getInputRealmLocation() == null || descriptor.getOutputRealmLocation() == null ||
                descriptor.getFileSystemRealmName() == null || descriptor.getCredentialStore() == null ||
                descriptor.getCreateCredentialStore() == null || descriptor.getSecretKeyAlias() == null ||
                descriptor.getHashEncoding() == null || descriptor.getHashCharset() == null ||
                descriptor.getEncoded() == null || descriptor.getLevels() == null || descriptor.getPopulate() == null || (
                        descriptor.getKeyStoreLocation() != null && descriptor.getPassword() == null && descriptor.getPasswordEnv() == null
        )) {
            warningHandler(ElytronToolMessages.msg.fileSystemEncryptRequiredParametersNotSpecified());
            return true;
        }
        return false;
    }

}