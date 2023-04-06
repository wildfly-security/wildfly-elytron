/*
 * Copyright 2023 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.tool;

import static org.wildfly.security.tool.ElytronTool.ElytronToolExitStatus_OK;
import static org.wildfly.security.tool.Params.BOOLEAN_ARG_REGEX;
import static org.wildfly.security.tool.Params.BOOLEAN_PARAM;
import static org.wildfly.security.tool.Params.BULK_CONVERT_PARAM;
import static org.wildfly.security.tool.Params.CREDENTIAL_STORE_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.DEBUG_PARAM;
import static org.wildfly.security.tool.Params.DEFAULT_KEY_PAIR_ALIAS;
import static org.wildfly.security.tool.Params.DEFAULT_LEVELS;
import static org.wildfly.security.tool.Params.DIRECTORY_PARAM;
import static org.wildfly.security.tool.Params.ENCODED_PARAM;
import static org.wildfly.security.tool.Params.FILE_PARAM;
import static org.wildfly.security.tool.Params.FILE_SEPARATOR;
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
import static org.wildfly.security.tool.Params.NUMBER_PARAM;
import static org.wildfly.security.tool.Params.OUTPUT_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.PASSWORD_ENV_PARAM;
import static org.wildfly.security.tool.Params.PASSWORD_PARAM;
import static org.wildfly.security.tool.Params.REALM_NAME_PARAM;
import static org.wildfly.security.tool.Params.SECRET_KEY_ALIAS_PARAM;
import static org.wildfly.security.tool.Params.SILENT_PARAM;
import static org.wildfly.security.tool.Params.SUMMARY_DIVIDER;
import static org.wildfly.security.tool.Params.SUMMARY_PARAM;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
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
 * Elytron Tool command to enable integrity checking in filesystem realms that previously did not have it enabled. If
 * any identities use a schema which doesn't support integrity checking ({@code urn:elytron:identity:1.1} or earlier),
 * they are also updated.
 *
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class FileSystemRealmIntegrityCommand extends Command {
    static final String FILE_SYSTEM_REALM_INTEGRITY_COMMAND = "filesystem-realm-integrity";

    static final String DEFAULT_FILESYSTEM_REALM_NAME = "filesystem-realm-with-integrity";
    static final String MISSING = "MISSING";

    private final List<Descriptor> descriptors = new ArrayList<>();
    static final List<String> PARAMS_LIST = new ArrayList<>(Arrays.asList(INPUT_LOCATION_PARAM, OUTPUT_LOCATION_PARAM,
            KEYSTORE_PARAM, PASSWORD_PARAM, KEY_PAIR_ALIAS_PARAM, CREDENTIAL_STORE_LOCATION_PARAM, SECRET_KEY_ALIAS_PARAM));

    private final Options options = new Options();
    private final CommandLineParser parser = new DefaultParser();
    private boolean silentMode = false;
    private boolean summaryMode = false;
    private final StringBuilder summaryString = new StringBuilder();
    private boolean warningOccurred = false;

    FileSystemRealmIntegrityCommand() {
        options.addOption(Option.builder("i").longOpt(INPUT_LOCATION_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemEncryptInputLocationDesc())
                        .hasArg().argName(DIRECTORY_PARAM)
                        .build());
        options.addOption(Option.builder("o").longOpt(OUTPUT_LOCATION_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityOutputLocationDesc())
                        .hasArg().argName(DIRECTORY_PARAM)
                        .build());
        options.addOption(Option.builder("r").longOpt(REALM_NAME_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityNewRealmDesc())
                        .hasArg().argName(NAME_PARAM)
                        .build());
        options.addOption(Option.builder("k").longOpt(KEYSTORE_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityKeyStoreDesc())
                        .hasArg().argName(FILE_PARAM)
                        .build());
        options.addOption(Option.builder("t").longOpt(KEYSTORE_TYPE_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityKeyStoreTypeDesc())
                        .hasArg().argName(NAME_PARAM)
                        .build());

        // Password by terminal or environment variable, optional
        options.addOptionGroup(new OptionGroup()
                        .addOption(Option.builder("p").longOpt(PASSWORD_PARAM).desc(ElytronToolMessages.msg.cmdLineKeyStorePassword())
                                .hasArg().argName(PASSWORD_PARAM)
                                .build())
                        .addOption(Option.builder("pe").longOpt(PASSWORD_ENV_PARAM).desc(ElytronToolMessages.msg.cmdLineKeyStorePasswordEnv())
                                .hasArg().argName(NAME_PARAM)
                                .build()));

        options.addOption(Option.builder("a").longOpt(KEY_PAIR_ALIAS_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityKeyPairAliasDesc())
                        .hasArg().argName(NAME_PARAM)
                        .build());

        // Other filesystem realm configuration options
        options.addOption(Option.builder("c").longOpt(CREDENTIAL_STORE_LOCATION_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityCredentialStoreDesc())
                        .hasArg().argName(FILE_PARAM)
                        .build());
        options.addOption(Option.builder("s").longOpt(SECRET_KEY_ALIAS_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegritySecretKeyDesc())
                        .hasArg().argName(NAME_PARAM)
                        .build());
        options.addOption(Option.builder("l").longOpt(LEVELS_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityLevelsDesc())
                        .hasArg().argName(NUMBER_PARAM)
                        .build());
        options.addOption(Option.builder("e").longOpt(HASH_ENCODING_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityHashEncodingDesc())
                        .hasArg().argName(NAME_PARAM)
                        .build());
        options.addOption(Option.builder("u").longOpt(HASH_CHARSET_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityHashCharsetDesc())
                        .hasArg().argName(NAME_PARAM)
                        .build());
        options.addOption(Option.builder("f").longOpt(ENCODED_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityEncodedDesc())
                        .hasArg().argName(BOOLEAN_PARAM)
                        .build());
        options.addOption(Option.builder("b").longOpt(BULK_CONVERT_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmIntegrityBulkConvertDesc())
                        .hasArg().argName(FILE_PARAM)
                        .build());

        // General options
        options.addOption(Option.builder("h").longOpt(HELP_PARAM).desc(ElytronToolMessages.msg.cmdLineHelp())
                        .build());
        options.addOption(Option.builder("d").longOpt(DEBUG_PARAM).desc(ElytronToolMessages.msg.cmdLineDebug())
                        .build());
        options.addOption(Option.builder().longOpt(SILENT_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmSilentDesc())
                        .build());
        options.addOption(Option.builder().longOpt(SUMMARY_PARAM).desc(ElytronToolMessages.msg.cmdFileSystemRealmSummaryDesc())
                        .build());
    }

    private static final class Descriptor {
        private Path inputRealmPath;
        private Path outputRealmPath;
        private String fileSystemRealmName;
        private Path keyStorePath;
        private String keyStoreType;
        private char[] password;
        private String passwordEnv;
        private String keyPairAlias;

        private Path credentialStorePath;
        private String secretKeyAlias;
        private Integer levels;
        private Encoding hashEncoding;
        private Charset hashCharset;
        private Boolean encoded;

        private Boolean upgradeInPlace;
        private Boolean missingRequiredValue;
        private Boolean realmUpgraded;

        Descriptor() {
            this.upgradeInPlace = false;
            this.missingRequiredValue = false;
            this.realmUpgraded = false;
        }

        Descriptor(Descriptor descriptor) {
            this.inputRealmPath = descriptor.inputRealmPath;
            this.outputRealmPath = descriptor.outputRealmPath;
            this.fileSystemRealmName = descriptor.fileSystemRealmName;
            this.keyStorePath = descriptor.keyStorePath;
            this.keyStoreType = descriptor.keyStoreType;
            this.password = descriptor.password;
            this.passwordEnv = descriptor.passwordEnv;
            this.keyPairAlias = descriptor.keyPairAlias;

            this.credentialStorePath = descriptor.credentialStorePath;
            this.secretKeyAlias = descriptor.secretKeyAlias;
            this.levels = descriptor.levels;
            this.hashEncoding = descriptor.hashEncoding;
            this.hashCharset = descriptor.hashCharset;
            this.encoded = descriptor.encoded;

            this.upgradeInPlace = descriptor.upgradeInPlace;
            this.missingRequiredValue = descriptor.missingRequiredValue;
            this.realmUpgraded = descriptor.realmUpgraded;
        }

        /**
         * Retrieve a value by name, as a string, or null if no value was found.
         *
         * @param param the long name of a parameter, like {@code KEYSTORE_PARAM}
         * */
        public String getString(String param) {
            switch (param) {
                case INPUT_LOCATION_PARAM: // Required param
                    if (inputRealmPath == null) {
                        return null;
                    } else if (inputRealmPath.endsWith(MISSING)) {
                        return MISSING;
                    } else {
                        return inputRealmPath.toString();
                    }
                case OUTPUT_LOCATION_PARAM:
                    return outputRealmPath != null ? outputRealmPath.toString() : null;
                case REALM_NAME_PARAM:
                    return fileSystemRealmName;
                case KEYSTORE_PARAM: // Required param
                    if (keyStorePath == null) {
                        return null;
                    } else if (keyStorePath.endsWith(MISSING)) {
                        return MISSING;
                    } else {
                        return keyStorePath.toString();
                    }
                case KEYSTORE_TYPE_PARAM:
                    return keyStoreType;
                case PASSWORD_PARAM: // Required param
                    return password != null ? new String(password) : null;
                case PASSWORD_ENV_PARAM:
                    return passwordEnv;
                case KEY_PAIR_ALIAS_PARAM:
                    return keyPairAlias;
                case CREDENTIAL_STORE_LOCATION_PARAM:
                    return credentialStorePath != null ? credentialStorePath.toString() : null;
                case SECRET_KEY_ALIAS_PARAM:
                    return secretKeyAlias;
                case LEVELS_PARAM:
                    return levels != null ? levels.toString() : null;
                case HASH_ENCODING_PARAM:
                    return hashEncoding != null ? hashEncoding.name() : null;
                case HASH_CHARSET_PARAM:
                    return hashCharset != null ? hashCharset.name() : null;
                case ENCODED_PARAM:
                    return encoded != null ? encoded.toString() : null;
                default:
                    return null;
            }
        }
        public Path getInputRealmPath() {
            return inputRealmPath;
        }
        public Path getOutputRealmPath() {
            return outputRealmPath;
        }
        public String getFileSystemRealmName() {
            return fileSystemRealmName;
        }
        public Path getKeyStorePath() {
            return keyStorePath;
        }
        public String getKeyStoreType() {
            return keyStoreType;
        }
        public char[] getPassword() {
            return password;
        }
        public String getPasswordEnv() {
            return passwordEnv;
        }
        public String getKeyPairAlias() {
            return keyPairAlias;
        }
        public Path getCredentialStorePath() {
            return credentialStorePath;
        }
        public String getSecretKeyAlias() {
            return secretKeyAlias;
        }
        public Integer getLevels() {
            return levels;
        }
        public Encoding getHashEncoding() {
            return hashEncoding;
        }
        public Charset getHashCharset() {
            return hashCharset;
        }
        public Boolean getEncoded() {
            return encoded;
        }
        public Boolean getUpgradeInPlace() {
            return upgradeInPlace;
        }
        public Boolean getMissingRequiredValue() {
            return missingRequiredValue;
        }

        /** @return if the filesystem realm was successfully upgraded. Used to determine if a CLI script should be generated. */
        public Boolean getRealmUpgraded() {
            return realmUpgraded;
        }

        public void setInputRealmPath(String inputRealmPath) {
            setInputRealmPath(Path.of(inputRealmPath).normalize().toAbsolutePath());
        }
        public void setInputRealmPath(Path inputRealmPath) {
            this.inputRealmPath = inputRealmPath.normalize().toAbsolutePath();
        }
        public void setOutputRealmPath(String outputRealmPath) {
            setOutputRealmPath(Path.of(outputRealmPath).normalize().toAbsolutePath());
        }
        public void setOutputRealmPath(Path outputRealmPath) {
            this.outputRealmPath = outputRealmPath.normalize().toAbsolutePath();
        }
        public void setFileSystemRealmName(String fileSystemRealmName) {
            this.fileSystemRealmName = fileSystemRealmName;
        }
        public void setKeyStorePath(String keyStorePath) {
            setKeyStorePath(Path.of(keyStorePath).normalize().toAbsolutePath());
        }
        public void setKeyStorePath(Path keyStorePath) {
            this.keyStorePath = keyStorePath.normalize().toAbsolutePath();
        }
        public void setKeyStoreType(String keyStoreType) {
            this.keyStoreType = keyStoreType;
        }
        public void setPassword(String password) {
            if (password != null) {
                setPassword(password.toCharArray());
            } else {
                setPassword((char[]) null);
            }
        }
        public void setPassword(char[] password) {
            this.password = password;
        }

        public void setPasswordEnv(String passwordEnv) {
            this.passwordEnv = passwordEnv;
        }
        public void setKeyPairAlias(String keyPairAlias) {
            this.keyPairAlias = keyPairAlias;
        }
        public void setCredentialStorePath(String credentialStorePath) {
            setCredentialStorePath(Path.of(credentialStorePath).normalize().toAbsolutePath());
        }
        public void setCredentialStorePath(Path credentialStorePath) {
            this.credentialStorePath = credentialStorePath.normalize().toAbsolutePath();
        }
        public void setSecretKeyAlias(String secretKeyAlias) {
            this.secretKeyAlias = secretKeyAlias;
        }
        public void setLevels(String levels) throws NumberFormatException {
            setLevels(Integer.parseInt(levels));
        }
        public void setLevels(Integer levels) {
            this.levels = levels;
        }
        public void setHashEncoding(String hashEncoding) throws IllegalArgumentException {
            setHashEncoding(Encoding.valueOf(hashEncoding.toUpperCase()));
        }
        public void setHashEncoding(Encoding hashEncoding) {
            this.hashEncoding = hashEncoding;
        }
        public void setHashCharset(String hashCharset) {
            setHashCharset(Charset.forName(hashCharset.toUpperCase()));
        }
        public void setHashCharset(Charset hashCharset) {
            this.hashCharset = hashCharset;
        }
        public void setEncoded(String encoded) throws IllegalArgumentException {
            if (BOOLEAN_ARG_REGEX.matcher(encoded).find()) {
                setEncoded(Boolean.parseBoolean(encoded));
            } else throw ElytronToolMessages.msg.encodedMustBeBoolean();
        }
        public void setEncoded(Boolean encoded) {
            this.encoded = encoded;
        }
        public void setUpgradeInPlace(Boolean upgradeInPlace) {
            this.upgradeInPlace = upgradeInPlace;
        }
        public void setMissingRequiredValue() {
            this.missingRequiredValue = true;
        }

        /** Set when filesystem realm is successfully upgraded. */
        public void setRealmUpgraded() {
            this.realmUpgraded = true;
        }

        void reset(boolean resetMissingValues) {
            // Required values are set to null if contents are null, or equal "MISSING"
            if (!Objects.equals(getString(INPUT_LOCATION_PARAM), MISSING)) { inputRealmPath = null; }
            if (!Objects.equals(getString(KEYSTORE_PARAM), MISSING)) { keyStorePath = null; }
            if (!Objects.equals(getString(PASSWORD_PARAM), MISSING)) { password = null; }

            outputRealmPath = null;
            fileSystemRealmName = null;
            keyStoreType = null;
            passwordEnv = null;
            keyPairAlias = null;
            credentialStorePath = null;
            secretKeyAlias = null;
            levels = null;
            hashEncoding = null;
            hashCharset = null;
            encoded = null;

            upgradeInPlace = false;
            realmUpgraded = false;
            if (resetMissingValues) {
                missingRequiredValue = false;
            }
        }
    }

    @Override
    public void execute(String[] args) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        CommandLine cmdLine = parser.parse(options, args, false);
        setEnableDebug(cmdLine.hasOption(DEBUG_PARAM));
        if (cmdLine.hasOption(HELP_PARAM)) {
            help();
            setStatus(ElytronToolExitStatus_OK);
            return;
        }
        if (cmdLine.hasOption(SILENT_PARAM)) {
            silentMode = true;
        }
        if (cmdLine.hasOption(SUMMARY_PARAM)) {
            summaryMode = true;
            summaryString.append(SUMMARY_DIVIDER);
            summaryString.append(LINE_SEPARATOR);
            summaryString.append("Summary for execution of Elytron Tool command filesystem-realm-integrity");
            summaryString.append(LINE_SEPARATOR);
            summaryString.append(SUMMARY_DIVIDER);
            summaryString.append(LINE_SEPARATOR);
        }
        printDuplicatesWarning(cmdLine);

        String inputRealmPathOption = cmdLine.getOptionValue("i");
        String outputRealmPathOption = cmdLine.getOptionValue("o");
        String realmNameOption = cmdLine.getOptionValue("r");
        String keyStorePathOption = cmdLine.getOptionValue("k");
        String keyStoreTypeOption = cmdLine.getOptionValue("t");
        String passwordOption = cmdLine.getOptionValue("p");
        String passwordEnvOption = cmdLine.getOptionValue("pe");
        String keyPairAliasOption = cmdLine.getOptionValue("a");
        String credentialStorePathOption = cmdLine.getOptionValue("c");
        String secretKeyAliasOption = cmdLine.getOptionValue("s");
        String levelsOption = cmdLine.getOptionValue("l");
        String hashEncodingOption = cmdLine.getOptionValue("e");
        String hashCharsetOption = cmdLine.getOptionValue("u");
        String encodedOption = cmdLine.getOptionValue("f");
        String bulkConvertOption = cmdLine.getOptionValue("b");

        if (bulkConvertOption == null) {
            if (summaryMode) {
                summaryString.append("Options were specified via CLI, converting single users-roles combination");
                summaryString.append(LINE_SEPARATOR);
            }
            Descriptor descriptor = new Descriptor();

            if (inputRealmPathOption == null) {
                errorHandler(ElytronToolMessages.msg.inputLocationNotSpecified());
            } else {
                Path inputPath = Path.of(inputRealmPathOption).normalize().toAbsolutePath();
                if (Files.notExists(inputPath)) {
                    errorHandler(ElytronToolMessages.msg.inputLocationDoesNotExist());
                }
                descriptor.setInputRealmPath(inputPath);
            }

            if (outputRealmPathOption != null) {
                Path outputPath = Path.of(outputRealmPathOption).normalize().toAbsolutePath();
                Files.createDirectories(outputPath); // Throws nothing if already exists
                descriptor.setOutputRealmPath(outputPath);
            }

            descriptor.setFileSystemRealmName(Objects.requireNonNullElse(realmNameOption, DEFAULT_FILESYSTEM_REALM_NAME));

            if (keyStorePathOption == null) {
                throw ElytronToolMessages.msg.keyStorePathNotSpecified();
            } else {
                Path keyStorePath = Path.of(keyStorePathOption);
                if (Files.notExists(keyStorePath)) {
                    throw ElytronToolMessages.msg.keyStoreDoesNotExist();
                }
                descriptor.setKeyStorePath(keyStorePath);
            }

            descriptor.setKeyStoreType(keyStoreTypeOption);

            if (passwordOption == null && passwordEnvOption == null) {
                passwordOption = prompt(false, ElytronToolMessages.msg.keyStorePasswordPrompt(), false, null);
                if (passwordOption == null) {
                    setStatus(GENERAL_CONFIGURATION_ERROR);
                    throw ElytronToolMessages.msg.optionNotSpecified(PASSWORD_PARAM + " or " + PASSWORD_ENV_PARAM);
                }
            } else if (passwordEnvOption != null) { // Resolve environment variable
                descriptor.setPasswordEnv(passwordEnvOption);
                passwordOption = System.getenv(passwordEnvOption);
            }
            descriptor.setPassword(passwordOption);

            descriptor.setKeyPairAlias(keyPairAliasOption);

            if (credentialStorePathOption != null) {
                Path credentialStorePath = Path.of(credentialStorePathOption);
                descriptor.setCredentialStorePath(credentialStorePath);
            }

            descriptor.setSecretKeyAlias(secretKeyAliasOption);

            if (levelsOption != null) {
                try {
                    descriptor.setLevels(levelsOption);
                } catch (NumberFormatException e) {
                    errorHandler(e);
                }
            }

            if (hashEncodingOption == null) {
                descriptor.setHashEncoding(Encoding.BASE64);
            } else {
                try {
                    descriptor.setHashEncoding(hashEncodingOption);
                } catch (IllegalArgumentException e) {
                    errorHandler(e);
                }
            }

            if (hashCharsetOption == null) {
                descriptor.setHashCharset(StandardCharsets.UTF_8);
            } else {
                try {
                    descriptor.setHashCharset(hashCharsetOption);
                } catch (IllegalArgumentException e) {
                    errorHandler(e);
                }
            }

            if (encodedOption == null) {
                descriptor.setEncoded(true);
            } else if (!BOOLEAN_ARG_REGEX.matcher(encodedOption).find()) {
                throw ElytronToolMessages.msg.encodedMustBeBoolean();
            } else {
                descriptor.setEncoded(Boolean.parseBoolean(encodedOption));
            }

            descriptors.add(descriptor);
            findMissingRequiredValuesAndSetValues(0, descriptor);
        } else if (nonBulkConvertOptionSet(inputRealmPathOption, outputRealmPathOption, realmNameOption, keyStorePathOption,
                        keyStoreTypeOption, passwordOption, passwordEnvOption, keyPairAliasOption, credentialStorePathOption,
                        secretKeyAliasOption, levelsOption, hashEncodingOption, hashCharsetOption, encodedOption)) {
            throw ElytronToolMessages.msg.mutuallyExclusiveOptionsIntegritySpecified();
        } else {
            if (summaryMode) {
                summaryString.append(String.format("Options were specified via descriptor file: %s, converting multiple old filesystem realm", bulkConvertOption));
                summaryString.append(LINE_SEPARATOR);
            }
            parseDescriptorFile(bulkConvertOption);
        }

        upgradeFileSystemRealm();
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

    /** Displays the help screen for the command */
    @Override
    public void help() {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(WIDTH);
        help.printHelp(ElytronToolMessages.msg.cmdHelp(getToolCommand(), FILE_SYSTEM_REALM_INTEGRITY_COMMAND),
                ElytronToolMessages.msg.cmdFileSystemIntegrityHelpHeader(),
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
            System.out.println(LINE_SEPARATOR + summaryString);
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
        summaryString.append("Found following filesystem realm combinations - MISSING indicates missing required parameter:");
        summaryString.append(LINE_SEPARATOR);
        for (int i = 0; i < count; i++) {
            StringBuilder summary = new StringBuilder();
            summary.append("\tPrinting summary for block ");
            summary.append(i + 1);
            summary.append(LINE_SEPARATOR);
            Descriptor descriptor = descriptors.get(i);
            for (String param : PARAMS_LIST) {
                String paramValue = descriptor.getString(param);

                summary.append("\t\t");
                summary.append(param);
                summary.append(" - ");

                if (param.equals(PASSWORD_PARAM)) {
                    summary.append(printPasswordSummary(paramValue));
                } else {
                    summary.append(descriptor.getString(param));
                }

                summary.append(LINE_SEPARATOR);
            }

            summaryString.append(summary);
        }
        summaryString.append(LINE_SEPARATOR);
    }

    private String printPasswordSummary(String paramValue) {
        if (paramValue == null) {
            return null;
        } else if (paramValue.equals(MISSING)) {
            return MISSING;
        } else {
            return "<masked>";
        }
    }

    /** @return if any provided options are set. Validates that {@code --bulk-convert} is exclusively set. */
    private boolean nonBulkConvertOptionSet(String... optionValues) {
        return Arrays.stream(optionValues).anyMatch(Objects::nonNull);
    }

    /**
     * Parses options provided in a descriptor file
     *
     * @throws Exception Exception to be handled by Elytron Tool
     */
    private void parseDescriptorFile(String file) throws Exception {
        Path path = Path.of(file);
        if (!Files.isRegularFile(path)) {
            errorHandler(ElytronToolMessages.msg.fileNotFound(file));
        }

        Descriptor descriptor = new Descriptor();
        AtomicInteger count = new AtomicInteger(1);
        try (Stream<String> stream = Files.lines(path)) {
            stream.forEach(line -> {
                if (line.isEmpty()) { // End of descriptor block
                    if (descriptor.getPasswordEnv() != null) {
                        // Password set by environment variable
                        descriptor.setPassword(System.getenv(descriptor.getPasswordEnv()));
                    }
                    copyAddResetDescriptor(count.intValue(), descriptor);
                    count.getAndIncrement();

                } else {
                    String[] parts = line.split(":");
                    String option = parts[0];
                    String arg = parts[1];
                    switch (option) {
                        case INPUT_LOCATION_PARAM:
                            descriptor.setInputRealmPath(arg);
                            break;
                        case OUTPUT_LOCATION_PARAM:
                            descriptor.setOutputRealmPath(arg);
                            break;
                        case REALM_NAME_PARAM:
                            descriptor.setFileSystemRealmName(arg);
                            break;
                        case KEYSTORE_PARAM:
                            descriptor.setKeyStorePath(arg);
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
                        case CREDENTIAL_STORE_LOCATION_PARAM:
                            descriptor.setCredentialStorePath(arg);
                            break;
                        case SECRET_KEY_ALIAS_PARAM:
                            descriptor.setSecretKeyAlias(arg);
                            break;
                        case LEVELS_PARAM:
                            descriptor.setLevels(arg);
                            break;
                        case HASH_ENCODING_PARAM:
                            descriptor.setHashEncoding(arg);
                            break;
                        case HASH_CHARSET_PARAM:
                            descriptor.setHashCharset(arg);
                            break;
                    }
                }
            });
        } catch (Exception e) {
            errorHandler(e);
        }

        copyAddResetDescriptor(count.intValue(), descriptor);
        if (summaryMode) {
            printDescriptorBlocks(count.intValue());
        }
        count.getAndIncrement();
    }

    /**
     * Validates a {@link Descriptor} and clones it into the list of descriptors
     *
     * @param original The original descriptor that is continually modified
     */
    private void copyAddResetDescriptor(int count, Descriptor original) {
        findMissingRequiredValuesAndSetValues(count, original);

        descriptors.add(new Descriptor(original));
        original.reset(true);
    }

    /**
     * Determines if the current descriptor block is missing any required values
     * and sets defaults for optional values. If a required value is missing,
     * prints a warning message and resets the descriptor block.
     *
     * @param count The index of the current descriptor block in {@code descriptors}.
     */
    private void findMissingRequiredValuesAndSetValues(int count, Descriptor descriptor) {
        if (descriptor.getInputRealmPath() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockInputLocation(count));
            descriptor.setInputRealmPath(MISSING);
            descriptor.setMissingRequiredValue();
        }
        if (descriptor.getKeyStorePath() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockKeyStorePath(count));
            descriptor.setKeyStorePath(MISSING);
            descriptor.setMissingRequiredValue();
        }
        if (descriptor.getPassword() == null) {
            // Password is loaded from environment variable after parsing CLI options or bulk conversion block
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockPassword(count));
            descriptor.setPassword(MISSING);
            descriptor.setMissingRequiredValue();
        }
        if (descriptor.getFileSystemRealmName() == null) { // Don't use zero-index for realm name
            if (count == 0) {
                descriptor.setFileSystemRealmName(DEFAULT_FILESYSTEM_REALM_NAME);
            } else {
                descriptor.setFileSystemRealmName(DEFAULT_FILESYSTEM_REALM_NAME + "-" + UUID.randomUUID());
            }
        }
        if (descriptor.getKeyPairAlias() == null) descriptor.setKeyPairAlias(DEFAULT_KEY_PAIR_ALIAS);
        if (descriptor.getLevels() == null) descriptor.setLevels(DEFAULT_LEVELS);
        if (descriptor.getHashEncoding() == null) descriptor.setHashEncoding(Encoding.BASE64);
        if (descriptor.getHashCharset() == null) descriptor.setHashCharset(StandardCharsets.UTF_8);
        if (descriptor.getEncoded() == null) descriptor.setEncoded(true);

        if (descriptor.getOutputRealmPath() == null) {
            descriptor.setUpgradeInPlace(true);
        }
        if (descriptor.getMissingRequiredValue()) {
            descriptor.reset(false);
        }
    }

    /**
     * Handles upgrading the Elytron filesystem realm from the descriptor array
     *
     * @throws Exception Exception to be handled by Elytron Tool
     */
    private void upgradeFileSystemRealm() throws Exception {
        int count = 0;
        for (Descriptor descriptor : descriptors) {
            count++;
            if (descriptor.getMissingRequiredValue()) {
                warningHandler(ElytronToolMessages.msg.skippingDescriptorBlock(count, "missing required parameter"));
                continue;
            }

            System.out.println(ElytronToolMessages.msg.fileSystemRealmIntegrityCreatingRealm(descriptor.getString(INPUT_LOCATION_PARAM)));

            // Load key pair
            KeyPair keyPair = getKeyPair(descriptor.getKeyStorePath(), descriptor.getKeyStoreType(), descriptor.getKeyPairAlias(),
                    descriptor.getPassword(), count);
            if (keyPair == null) continue;

            // Configure existing and new filesystem realms
            Path inputPath = descriptor.getInputRealmPath();
            Path outputPath = descriptor.getOutputRealmPath();
            if (inputPath == null) {
                warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockInputLocation(count));
                continue;
            }

            // Configure output path for realm name or in-place upgrade
            if (descriptor.getUpgradeInPlace()) {
                Path backupPath = backupInputFileSystemRealm(descriptor, count);
                if (backupPath == null) {
                    outputPath = Path.of(inputPath.toString().replaceFirst(Pattern.quote(FILE_SEPARATOR + "*$"), "") + "-with-integrity");

                    descriptor.setUpgradeInPlace(false);
                    warningHandler(ElytronToolMessages.msg.unableToUpgradeInPlace(inputPath.toString(), outputPath.toString()));
                } else {
                    outputPath = inputPath;
                    inputPath = backupPath;
                }

                // Update output path for CLI script generation
                descriptor.setOutputRealmPath(outputPath);
            } else {
                outputPath = outputPath.resolve(descriptor.getFileSystemRealmName());
            }

            FileSystemSecurityRealmBuilder inputFileSystemRealmBuilder = FileSystemSecurityRealm.builder()
                    .setRoot(inputPath)
                    .setLevels(descriptor.getLevels())
                    .setHashEncoding(descriptor.getHashEncoding())
                    .setHashCharset(descriptor.getHashCharset())
                    .setEncoded(descriptor.getEncoded())
                    .setProviders(ELYTRON_KS_PASS_PROVIDERS);

            FileSystemSecurityRealmBuilder outputFileSystemRealmBuilder = FileSystemSecurityRealm.builder()
                    .setRoot(outputPath)
                    .setPrivateKey(keyPair.getPrivate())
                    .setPublicKey(keyPair.getPublic())
                    .setLevels(descriptor.getLevels())
                    .setHashCharset(descriptor.getHashCharset())
                    .setProviders(ELYTRON_KS_PASS_PROVIDERS);

            // Load encryption SecretKey if provided
            if (descriptor.getCredentialStorePath() != null) {
                SecretKey secretKey = getSecretKey(false, descriptor.getString(CREDENTIAL_STORE_LOCATION_PARAM),
                        descriptor.getSecretKeyAlias(), false, count);
                if (secretKey != null) {
                    inputFileSystemRealmBuilder.setSecretKey(secretKey);
                    outputFileSystemRealmBuilder.setSecretKey(secretKey);
                } else continue;
            }

            FileSystemSecurityRealm inputRealm = inputFileSystemRealmBuilder.build();
            if (!inputRealm.getRealmIdentityIterator().hasNext()) {
                warningHandler(ElytronToolMessages.msg.skippingDescriptorBlockEmptyRealm(count));
                continue;
            }

            FileSystemRealmUtil.cloneIdentitiesToNewRealm(
                    inputRealm,
                    outputFileSystemRealmBuilder.build());

            descriptor.setRealmUpgraded();
        }
    }

    /**
     * Generates the CLI commands the user must run for Elytron to recognize
     * and use the new filesystem-realm, and saves them to a file
     */
    private void createWildFlyScript() throws Exception {
        int counter = 0;
        for (Descriptor descriptor : descriptors) {
            counter++;
            if (!descriptor.getRealmUpgraded()) {
                continue;
            }

            String fileSystemRealmName = descriptor.getFileSystemRealmName();
            Path outputRealmPath = descriptor.getOutputRealmPath();
            boolean upgradeInPlace = descriptor.getUpgradeInPlace();

            String createScriptCheck = "";
            Path scriptPath = Path.of(String.format("%s/%s.cli", outputRealmPath, fileSystemRealmName));

            // Ask to overwrite CLI script, if already exists
            if(scriptPath.toFile().exists()) {
                createScriptCheck = prompt(
                        true,
                        ElytronToolMessages.msg.shouldFileBeOverwritten(scriptPath.toString()),
                        false,
                        null
                );
                if (createScriptCheck.trim().isEmpty()) createScriptCheck = "n";
            }

            boolean overwriteScript = createScriptCheck.isEmpty() || createScriptCheck.toLowerCase().startsWith("y");
            if (!overwriteScript) {
                do {
                    scriptPath = Path.of(String.format("%s/%s.cli",
                            outputRealmPath,
                            fileSystemRealmName + "-" + UUID.randomUUID()));
                } while (scriptPath.toFile().exists());
            }

            if (summaryMode) {
                summaryString.append(String.format("Configured script for WildFly named %s.cli at %s.", fileSystemRealmName, outputRealmPath));
                summaryString.append(LINE_SEPARATOR);
                summaryString.append(String.format("Name of filesystem-realm: %s", fileSystemRealmName));
                summaryString.append(LINE_SEPARATOR);
            }

            ArrayList<String> scriptLines = new ArrayList<>(Arrays.asList(
                String.format("/subsystem=elytron/key-store=%s:add(path=%s, credential-reference={clear-text=\"%s\"}%s)",
                        "mykeystore"+counter,
                        descriptor.getKeyStorePath(),
                        descriptor.getString(PASSWORD_PARAM),
                        descriptor.getKeyStoreType() != null ? ", type="+descriptor.getKeyStoreType() : ""),
                String.format("/subsystem=elytron/filesystem-realm=%s:add(path=%s%s%s, key-store=%s, key-store-alias=%s%s%s)",
                        fileSystemRealmName,
                        upgradeInPlace ? outputRealmPath : outputRealmPath.toString() + FILE_SEPARATOR + fileSystemRealmName,
                        descriptor.getCredentialStorePath() != null ? ", credential-store=mycredstore" + counter : "",
                        descriptor.getSecretKeyAlias() != null ?  ", secret-key="+descriptor.getSecretKeyAlias() : "",
                        "mykeystore"+counter,
                        descriptor.getKeyPairAlias(),
                        !descriptor.getLevels().equals(DEFAULT_LEVELS) ? ", levels="+descriptor.getLevels() : "",
                        descriptor.getHashCharset() != StandardCharsets.UTF_8 ? ", hash-charset="+descriptor.getHashCharset() : "")
            ));

            if (descriptor.getCredentialStorePath() != null) {
                // Credential store must be added before encrypted realm
                scriptLines.add(1, String.format("/subsystem=elytron/secret-key-credential-store=%s:add(path=%s)",
                        "mycredstore"+counter, descriptor.getCredentialStorePath()));
            }

            if (overwriteScript) { // Create a new script file, or append the existing one
                Files.write(scriptPath, scriptLines, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            } else {
                Files.write(scriptPath, scriptLines, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
        }
    }

    /**
     * Backup input filesystem realm to a new location, and delete original folder
     *
     * @param descriptor the current descriptor block
     * @return the {@link Path} of the backup directory, in format {@code <input_location>-backup[number]},
     * or {@code null} if the directory could not be backed up.
     * @throws Exception if an error occurs while deleting the old directory.
     */
    private Path backupInputFileSystemRealm(Descriptor descriptor, int count) throws Exception {
        Path originalDirectory = descriptor.getInputRealmPath();
        Path backupDirectory = Path.of(descriptor.getString(INPUT_LOCATION_PARAM)
                    .replaceFirst(Pattern.quote(FILE_SEPARATOR + "*$"), "") + "-backup");

        // Append number if directory already exists
        if (backupDirectory.toFile().exists()) {
            Path numBackupDirectory;
            do {
                numBackupDirectory = Path.of(backupDirectory + "-" + UUID.randomUUID());
            } while (numBackupDirectory.toFile().exists());

            backupDirectory = numBackupDirectory;
        }

        // Copy the filesystem realm
        try {
            final Path finalBackupDirectory = backupDirectory;
            Files.walkFileTree(originalDirectory, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    Files.createDirectories(finalBackupDirectory.resolve(originalDirectory.relativize(dir)));
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.copy(file, finalBackupDirectory.resolve(originalDirectory.relativize(file)));
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException | RuntimeException e) {
            return null;
        }

        // Delete current contents if backup is successful
        try {
            Files.walkFileTree(originalDirectory, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (file.toFile().delete()) {
                        return FileVisitResult.CONTINUE;
                    } else {
                        throw new IOException("Unable to delete " + file);
                    }
                }
            });
        } catch (IOException | RuntimeException e) {
            errorHandler(e);
        }

        System.out.println(ElytronToolMessages.msg.fileSystemRealmIntegrityInPlaceBackup(count, backupDirectory.toString()));
        return backupDirectory;
    }
}