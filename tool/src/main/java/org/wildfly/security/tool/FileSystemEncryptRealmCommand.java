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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.wildfly.security.auth.realm.FileSystemRealmUtil;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.PropertiesCredentialStore;
import org.wildfly.security.encryption.SecretKeyUtil;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.spec.Encoding;

/**
 * Elytron-Tool command to convert un-encrypted FileSystemRealms into an encrypted realm with the use of a SecretKey.
 * Also, optionally provides a WildFly CLI script to register the FileSystemRealm and corresponding
 * security-domain in WildFly.
 * @author <a href="mailto:araskar@redhat.com">Ashpan Raskar</a>
 */

class FileSystemEncryptRealmCommand extends Command {
    static final int GENERAL_CONFIGURATION_WARNING = 1;
    static final String FILE_SYSTEM_ENCRYPT_COMMAND = "filesystem-realm-encrypt";
    static final int SUMMARY_WIDTH = 100;

    private static final String HELP_PARAM = "help";
    private static final String DEBUG_PARAM = "debug";
    private static final String SILENT_PARAM = "silent";
    private static final String SUMMARY_PARAM = "summary";
    private static final String INPUT_REALM_LOCATION_PARAM = "input-location";
    private static final String REALM_NAME_PARAM = "realm-name";
    private static final String OUTPUT_REALM_LOCATION_PARAM = "output-location";
    private static final String CREDENTIAL_STORE_LOCATION_PARAM = "credential-store";
    private static final String CREATE_CREDENTIAL_STORE_PARAM = "create";
    private static final String SECRET_KEY_ALIAS_PARAM = "secret-key";
    private static final String HASH_ENCODING_PARAM = "hash-encoding";
    private static final String ENCODED_PARAM = "encoded";
    private static final String LEVELS_PARAM = "levels";
    private static final String POPULATE_SECRET_KEY_PARAM = "populate";
    private static final String BULK_CONVERT_PARAM = "bulk-convert";
    private static final String FILE_ARG = "file";
    private static final String DIRECTORY_ARG = "directory";
    private static final String NAME_ARG = "name";
    private static final String DEFAULT_FILESYSTEM_REALM_NAME = "encrypted-filesystem-realm";
    public static Supplier<Provider[]> ELYTRON_PASSWORD_PROVIDERS = () -> new Provider[]{
            WildFlyElytronPasswordProvider.getInstance()
    };

    private final List<Descriptor> descriptors = new ArrayList<>();
    private final List<String> PARAMS_LIST = new ArrayList<>(Arrays.asList(INPUT_REALM_LOCATION_PARAM, OUTPUT_REALM_LOCATION_PARAM));

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

        option = new Option("i", INPUT_REALM_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptInputLocationDesc());
        option.setArgName(DIRECTORY_ARG);
        options.addOption(option);

        option = new Option("r", REALM_NAME_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptNewRealmDesc());
        option.setArgName(DIRECTORY_ARG);
        options.addOption(option);

        option = new Option("o", OUTPUT_REALM_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptOutputLocationDesc());
        option.setArgName(DIRECTORY_ARG);
        options.addOption(option);

        option = new Option("c", CREDENTIAL_STORE_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptCredentialStoreDesc());
        option.setArgName(FILE_ARG);
        options.addOption(option);

        option = new Option("a", CREATE_CREDENTIAL_STORE_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptCreateCredentialStoreDesc());
        option.setArgName(NAME_ARG);
        options.addOption(option);

        option = new Option("s", SECRET_KEY_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptSecretKeyDesc());
        option.setArgName(NAME_ARG);
        options.addOption(option);

        option = new Option("e", HASH_ENCODING_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptHashEncodingDesc());
        option.setArgName(NAME_ARG);
        options.addOption(option);

        option = new Option("f", ENCODED_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptEncodedDesc());
        option.setArgName(NAME_ARG);
        options.addOption(option);

        option = new Option("l", LEVELS_PARAM, true, ElytronToolMessages.msg.cmdFileSystemEncryptLevelsDesc());
        option.setArgName(NAME_ARG);
        options.addOption(option);

        option = new Option("p", POPULATE_SECRET_KEY_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmEncryptPopulateDesc());
        option.setArgName(NAME_ARG);
        options.addOption(option);

        option = new Option("b", BULK_CONVERT_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmEncryptBulkConvertDesc());
        option.setArgName(FILE_ARG);
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
        private Integer levels;
        private Encoding hashEncoding;
        private Boolean encoded;
        private Boolean createCredentialStore;
        private Boolean populate;
        Descriptor() {
        }

        Descriptor(Descriptor descriptor) {
            this.inputRealmLocation = descriptor.inputRealmLocation;
            this.outputRealmLocation = descriptor.outputRealmLocation;
            this.fileSystemRealmName = descriptor.fileSystemRealmName;
            this.credentialStore = descriptor.credentialStore;
            this.hashEncoding = descriptor.hashEncoding;
            this.levels = descriptor.levels;
            this.encoded = descriptor.encoded;
            this.createCredentialStore = descriptor.createCredentialStore;
            this.secretKeyAlias = descriptor.secretKeyAlias;
            this.populate = descriptor.populate;
        }

        public Encoding getHashEncoding() {
            return hashEncoding;
        }

        public void setHashEncoding(Encoding hashEncoding) {
            this.hashEncoding = hashEncoding;
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

        void reset() {
            this.inputRealmLocation = null;
            this.outputRealmLocation = null;
            this.fileSystemRealmName = null;
            this.credentialStore = null;
            this.createCredentialStore = null;
            this.secretKeyAlias = null;
            this.hashEncoding = null;
            this.encoded = null;
            this.levels = null;
            this.populate = null;
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
            summaryString.append(String.join("", Collections.nCopies(SUMMARY_WIDTH, "-")));
            summaryString.append(System.getProperty("line.separator"));
            summaryString.append("Summary for execution of Elytron-Tool command FileSystemRealmEncrypt");
            summaryString.append(System.getProperty("line.separator"));
            summaryString.append(String.join("", Collections.nCopies(SUMMARY_WIDTH, "-")));
            summaryString.append(System.getProperty("line.separator"));
        }
        printDuplicatesWarning(cmdLine);

        String realmNameOption = cmdLine.getOptionValue("r");
        String inputRealmLocationOption = cmdLine.getOptionValue("i");
        String outputRealmLocationOption = cmdLine.getOptionValue("o");
        String credentialStoreOption = cmdLine.getOptionValue("c");
        String createCredentialStore = cmdLine.getOptionValue("a");
        String secretKeyAliasOption = cmdLine.getOptionValue("s");
        String hashEncodingOption = cmdLine.getOptionValue("e");
        String levelsOption = cmdLine.getOptionValue("l");
        String encodedOption = cmdLine.getOptionValue("f");
        String bulkConvert = cmdLine.getOptionValue("b");
        String populateOption = cmdLine.getOptionValue("p");

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
            if (populateOption == null) {
                descriptor.setPopulate(true);
            } else {
                descriptor.setPopulate(Boolean.valueOf(populateOption));
            }

            if (levelsOption == null) {
                descriptor.setLevels(2);
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
                descriptor.setSecretKeyAlias("key");
            }
            descriptors.add(descriptor);
            checkDescriptorFields(descriptor);
        } else if (inputRealmLocationOption != null || outputRealmLocationOption != null || secretKeyAliasOption != null ||
                realmNameOption != null || credentialStoreOption != null || createCredentialStore != null ||
                hashEncodingOption != null || encodedOption != null || levelsOption != null || populateOption != null) {
            throw ElytronToolMessages.msg.mutuallyExclusiveOptionsEncryptSpecified();
        } else {
            if (summaryMode) {
                summaryString.append(String.format("Options were specified via descriptor file: %s, converting multiple old filesystem realm", bulkConvert));
                summaryString.append(System.getProperty("line.separator"));
            }
            parseDescriptorFile(bulkConvert);
        }

        createFileSystemRealm();
        createWildFlyScript();

        if (summaryMode) {
            summaryString.append(String.join("", Collections.nCopies(SUMMARY_WIDTH, "-")));
            summaryString.append(System.getProperty("line.separator"));
            summaryString.append("End of summary");
            summaryString.append(System.getProperty("line.separator"));
            summaryString.append(String.join("", Collections.nCopies(SUMMARY_WIDTH, "-")));
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
    private void warningHandler(String warning) {
        warningOccurred = true;
        if (!silentMode) {
            System.out.print("WARNING: ");
            System.out.println(warning);
        }
        if (summaryMode) {
            summaryString.append("WARNING: ");
            summaryString.append(warning);
            summaryString.append(System.getProperty("line.separator"));
        }
    }

    /**
     * Determines if a summary needs to be printed and prints summary after an error is thrown
     *
     * @param e The exception thrown during execution
     * @throws Exception The exception to be handled by Elytron Tool
     */
    private void errorHandler(Exception e) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        if (summaryMode) {
            summaryString.append("Error was thrown during execution:");
            summaryString.append(System.getProperty("line.separator"));
            summaryString.append(e.getMessage());
            System.out.println(System.getProperty("line.separator") + summaryString.toString());
        }
        throw e;
    }

    /**
     * Prints out information found in a descriptor file for summary mode
     *
     * @param count The amount of descriptor blocks in the file
     */
    private void printDescriptorBlocks(int count) {
        summaryString.append(System.getProperty("line.separator"));
        summaryString.append(System.getProperty("line.separator"));
        summaryString.append("Found following unencrypted filesystem-realm combinations, null indicates missing required component:");
        summaryString.append(System.getProperty("line.separator"));
        for (int i = 0; i < count; i++) {
            StringBuilder summary = new StringBuilder();
            summary.append("\tPrinting summary for block ");
            summary.append(i + 1);
            summary.append(System.getProperty("line.separator"));
            Descriptor descriptor = descriptors.get(i);
            for (String param : PARAMS_LIST) {
                summary.append("\t\t");
                summary.append(param);
                summary.append(" - ");
                summary.append(getDescriptorParam(param, descriptor));
                summary.append(System.getProperty("line.separator"));
            }
            summaryString.append(summary);
        }
        summaryString.append(System.getProperty("line.separator"));
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
            case INPUT_REALM_LOCATION_PARAM:
                return descriptor.getInputRealmLocation();
            case OUTPUT_REALM_LOCATION_PARAM:
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
                    findMissingRequiredValuesAndSetValues(count.intValue(), descriptor);
                    copyAddResetDescriptor(descriptor);
                    count.getAndIncrement();
                } else {
                    String[] parts = line.split(":");
                    String option = parts[0];
                    String arg = parts[1];
                    switch (option) {
                        case INPUT_REALM_LOCATION_PARAM:
                            descriptor.setInputRealmLocation(arg);
                            break;
                        case OUTPUT_REALM_LOCATION_PARAM:
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
                        case HASH_ENCODING_PARAM:
                            descriptor.setHashEncoding(Encoding.valueOf(arg.toUpperCase()));
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
            descriptor.setFileSystemRealmName(DEFAULT_FILESYSTEM_REALM_NAME);
        }
        if(descriptor.getHashEncoding() == null) {
            descriptor.setHashEncoding(Encoding.BASE64);
        }
        if(descriptor.getEncoded() == null) {
            descriptor.setEncoded(true);
        }
        if(descriptor.getLevels() == null) {
            descriptor.setLevels(2);
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
            descriptor.setSecretKeyAlias("key");
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
        for (Descriptor descriptor : descriptors) {
            System.out.println(ElytronToolMessages.msg.fileSystemRealmEncryptCreatingRealm(descriptor.getInputRealmLocation()));

            if (checkDescriptorFields(descriptor)) continue;
            CredentialStore credentialStore;
            // check if credential-store and secret-key-alias are both specified, or both null
            String csType = PropertiesCredentialStore.NAME;
            try {
                credentialStore = CredentialStore.getInstance(csType);
            } catch (NoSuchAlgorithmException e) {
                // fallback to load all possible providers
                credentialStore = CredentialStore.getInstance(csType, getProvidersSupplier(null));
            }
            Map<String, String> implProps = new HashMap<>();
            implProps.put("create", String.valueOf(descriptor.getCreateCredentialStore()));
            implProps.put("location", descriptor.getCredentialStore());
            implProps.put("modifiable", Boolean.TRUE.toString());
            credentialStore.initialize(implProps);
            try {
                credentialStore.retrieve(descriptor.getSecretKeyAlias(), SecretKeyCredential.class).getSecretKey();
                System.out.println(ElytronToolMessages.msg.existingCredentialStore());
            } catch (Exception e) {
                if (!descriptor.getCreateCredentialStore()) {
                    warningHandler(ElytronToolMessages.msg.skippingBlockMissingCredentialStore());
                    continue;
                }
                if (descriptor.getPopulate()) {
                    SecretKey key = SecretKeyUtil.generateSecretKey(256);
                    Credential keyCredential = new SecretKeyCredential(key);
                    credentialStore.store(descriptor.getSecretKeyAlias(), keyCredential);
                    credentialStore.flush();
                } else {
                    errorHandler(ElytronToolMessages.msg.cmdFileSystemPopulateUnspecified());
                }
            }
            SecretKey key;
            try {
                key = credentialStore.retrieve(descriptor.getSecretKeyAlias(), SecretKeyCredential.class).getSecretKey();
            } catch (NullPointerException e) {
                System.out.println(ElytronToolMessages.msg.cmdFileSystemEncryptionNoSecretKey(descriptor.getCredentialStore(), descriptor.getInputRealmLocation()));
                continue;
            }

            FileSystemSecurityRealm oldFileSystemRealm = FileSystemSecurityRealm.builder()
                    .setRoot(Paths.get(descriptor.getInputRealmLocation()))
                    .setLevels(descriptor.getLevels())
                    .setHashEncoding(descriptor.getHashEncoding())
                    .setEncoded(descriptor.getEncoded())
                    .setProviders(ELYTRON_PASSWORD_PROVIDERS)
                    .build();

            FileSystemSecurityRealm newFileSystemRealm = FileSystemSecurityRealm.builder()
                    .setRoot(Paths.get(descriptor.getOutputRealmLocation(), descriptor.getFileSystemRealmName()))
                    .setSecretKey(key)
                    .setLevels(descriptor.getLevels())
                    .setProviders(ELYTRON_PASSWORD_PROVIDERS)
                    .build();
            FileSystemRealmUtil.createEncryptedRealmFromUnencrypted(oldFileSystemRealm, newFileSystemRealm);
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

            if(secretKeyAlias == null) {
                secretKeyAlias = "key";
            }
            String createScriptCheck = "";
            if (Paths.get(String.format("%s.cli", fileSystemRealmName)).toFile().exists()) {
                createScriptCheck = prompt(
                        false,
                        null,
                        false,
                        ElytronToolMessages.msg.shouldFileBeOverwritten(String.format("%s.cli", fileSystemRealmName))
                );
            }
            String fullOutputPath;
            if (outputRealmLocation.startsWith(".")) {
                fullOutputPath = Paths.get(outputRealmLocation.substring(2)).toAbsolutePath().toString();
            } else {
                fullOutputPath = Paths.get(outputRealmLocation).toAbsolutePath().toString();
            }

            if (summaryMode) {
                summaryString.append(String.format("Configured script for WildFly named %s.cli at %s.", fileSystemRealmName, fullOutputPath));
                summaryString.append(System.getProperty("line.separator"));
                summaryString.append("The script is using the following names:");
                summaryString.append(System.getProperty("line.separator"));
                summaryString.append(String.format("Name of filesystem-realm: %s", fileSystemRealmName));
                summaryString.append(System.getProperty("line.separator"));
            }

            List<String> scriptLines = Arrays.asList(
                String.format("/subsystem=elytron/secret-key-credential-store=%s:add(path=%s)", "mycredstore"+counter, credentialStore),
                String.format("/subsystem=elytron/filesystem-realm=%s:add(path=%s, levels=%s, credential-store=%s, secret-key=%s)", fileSystemRealmName, fullOutputPath+'/'+fileSystemRealmName, levels, "mycredstore"+counter, secretKeyAlias)
            );

            if (!createScriptCheck.equals("y") && !createScriptCheck.equals("yes")) {
                Files.write(Paths.get(String.format("%s/%s.cli", outputRealmLocation, fileSystemRealmName)), scriptLines, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            } else {
                Files.write(Paths.get(String.format("%s/%s.cli", outputRealmLocation, fileSystemRealmName)), scriptLines, StandardOpenOption.APPEND);
            }
            counter++;
        }
    }

    private boolean checkDescriptorFields(Descriptor descriptor) {
        if (descriptor.getInputRealmLocation() == null || descriptor.getOutputRealmLocation() == null ||
                descriptor.getFileSystemRealmName() == null || descriptor.getCredentialStore() == null ||
                descriptor.getCreateCredentialStore() == null || descriptor.getSecretKeyAlias() == null ||
                descriptor.getHashEncoding() == null || descriptor.getEncoded() == null ||
                descriptor.getLevels() == null || descriptor.getPopulate() == null) {
            warningHandler(ElytronToolMessages.msg.fileSystemEncryptRequiredParametersNotSpecified());
            return true;
        }
        return false;
    }

}