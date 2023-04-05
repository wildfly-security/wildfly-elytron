/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2018 Red Hat, Inc. and/or its affiliates.
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

import static org.wildfly.security.tool.Params.BULK_CONVERT_PARAM;
import static org.wildfly.security.tool.Params.DEBUG_PARAM;
import static org.wildfly.security.tool.Params.DIRECTORY_PARAM;
import static org.wildfly.security.tool.Params.FILE_PARAM;
import static org.wildfly.security.tool.Params.HELP_PARAM;
import static org.wildfly.security.tool.Params.LINE_SEPARATOR;
import static org.wildfly.security.tool.Params.NAME_PARAM;
import static org.wildfly.security.tool.Params.OUTPUT_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.SILENT_PARAM;
import static org.wildfly.security.tool.Params.SUMMARY_DIVIDER;
import static org.wildfly.security.tool.Params.SUMMARY_PARAM;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.lang3.ArrayUtils;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;

/**
 * Elytron-Tool command to convert legacy properties file into a FileSystemRealm.
 * Also, optionally provides a WildFly CLI script to register the FileSystemRealm and corresponding
 * security-domain in WildFly.
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
class FileSystemRealmCommand extends Command {

    static final String FILE_SYSTEM_REALM_COMMAND = "filesystem-realm";

    private static final String USERS_FILE_PARAM = "users-file";
    private static final String ROLES_FILE_PARAM = "roles-file";
    private static final String FILESYSTEM_REALM_NAME_PARAM = "filesystem-realm-name";
    private static final String SECURITY_DOMAIN_NAME_PARAM = "security-domain-name";
    private static final String DEFAULT_FILESYSTEM_REALM_NAME = "converted-properties-filesystem-realm";
    private static final String DEFAULT_SECURITY_DOMAIN_NAME = "converted-properties-security-domain";

    private List<Descriptor> descriptors = new ArrayList<>();
    private final List<String> PARAMS_LIST = new ArrayList<>(Arrays.asList(USERS_FILE_PARAM, ROLES_FILE_PARAM, OUTPUT_LOCATION_PARAM, FILESYSTEM_REALM_NAME_PARAM, SECURITY_DOMAIN_NAME_PARAM));

    private Options options;
    private CommandLineParser parser = new DefaultParser();
    private CommandLine cmdLine = null;
    private boolean silentMode = false;
    private boolean summaryMode = false;
    private StringBuilder summaryString = null;
    private boolean warningOccurred = false;

    FileSystemRealmCommand() {
        options = new Options();
        Option option;

        option = new Option("u", USERS_FILE_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmUsersFileDesc());
        option.setArgName(FILE_PARAM);
        options.addOption(option);

        option = new Option("r", ROLES_FILE_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmRolesFileDesc());
        option.setArgName(FILE_PARAM);
        options.addOption(option);

        option = new Option("o", OUTPUT_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmOutputLocationDesc());
        option.setArgName(DIRECTORY_PARAM);
        options.addOption(option);

        option = new Option("b", BULK_CONVERT_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmBulkConvertDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        option = new Option("f", FILESYSTEM_REALM_NAME_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmFileSystemRealmNameDesc());
        option.setArgName(NAME_PARAM);
        options.addOption(option);

        option = new Option("s", SECURITY_DOMAIN_NAME_PARAM, true, ElytronToolMessages.msg.cmdFileSystemRealmSecurityDomainNameDesc());
        option.setArgName(NAME_PARAM);
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
        private String usersFile;
        private String rolesFile;
        private String outputLocation;
        private String fileSystemRealmName;
        private String securityDomainName;
        private String realmName;

        Descriptor() {
        }

        Descriptor(Descriptor descriptor) {
            this.usersFile = descriptor.usersFile;
            this.rolesFile = descriptor.rolesFile;
            this.outputLocation = descriptor.outputLocation;
            this.fileSystemRealmName = descriptor.fileSystemRealmName;
            this.securityDomainName = descriptor.securityDomainName;
            this.realmName = descriptor.realmName;
        }

        String getUsersFile() {
            return this.usersFile;
        }

        String getRolesFile() {
            return this.rolesFile;
        }

        String getOutputLocation() {
            return this.outputLocation;
        }

        String getFileSystemRealmName() {
            return this.fileSystemRealmName;
        }

        String getSecurityDomainName() {
            return this.securityDomainName;
        }

        String getRealmName() {
            return this.realmName;
        }

        void setUsersFile(String usersFile) {
            this.usersFile = usersFile;
        }

        void setRolesFile(String rolesFile) {
            this.rolesFile = rolesFile;
        }

        void setOutputLocation(String outputLocation) {
            this.outputLocation = outputLocation;
        }

        void setFileSystemRealmName(String fileSystemRealmName) {
            this.fileSystemRealmName = fileSystemRealmName;
        }

        void setSecurityDomainName(String securityDomainName) {
            this.securityDomainName = securityDomainName;
        }

        void setRealmName(String realmName) {
            this.realmName = realmName;
        }

        void reset() {
            this.usersFile = null;
            this.rolesFile = null;
            this.outputLocation = null;
            this.fileSystemRealmName = null;
            this.securityDomainName = null;
            this.realmName = null;
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
            summaryString.append("Summary for execution of Elytron-Tool command FileSystemRealm");
            summaryString.append(LINE_SEPARATOR);
            summaryString.append(SUMMARY_DIVIDER);
            summaryString.append(LINE_SEPARATOR);
        }
        printDuplicatesWarning(cmdLine);

        String bulkConvert = cmdLine.getOptionValue("b");
        String usersFileOption = cmdLine.getOptionValue("u");
        String rolesFileOption = cmdLine.getOptionValue("r");
        String outputLocationOption = cmdLine.getOptionValue("o");

        if (bulkConvert == null) {
            if (summaryMode) {
                summaryString.append("Options were specified via CLI, converting single users-roles combination");
                summaryString.append(LINE_SEPARATOR);
            }

            if (usersFileOption == null) {
                errorHandler(ElytronToolMessages.msg.missingUsersFile());
            } else if (rolesFileOption == null) {
                errorHandler(ElytronToolMessages.msg.missingRolesFile());
            } else if (outputLocationOption == null) {
                errorHandler(ElytronToolMessages.msg.missingOutputLocation());
            }

            Descriptor descriptor = new Descriptor();
            descriptor.setUsersFile(usersFileOption);
            descriptor.setRolesFile(rolesFileOption);
            descriptor.setOutputLocation(outputLocationOption);
            descriptor.setFileSystemRealmName(cmdLine.getOptionValue("f"));
            descriptor.setSecurityDomainName(cmdLine.getOptionValue("s"));
            descriptors.add(descriptor);

            findMissingRequiredValuesAndSetValues(0, descriptor);
        } else if (usersFileOption != null || rolesFileOption != null || outputLocationOption != null) {
            throw ElytronToolMessages.msg.mutuallyExclusiveOptionsSpecified();
        } else {
            if (summaryMode) {
                summaryString.append(String.format("Options were specified via descriptor file: %s, converting multiple users-roles combinations", bulkConvert));
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
        help.printHelp(ElytronToolMessages.msg.cmdHelp(getToolCommand(), FILE_SYSTEM_REALM_COMMAND),
                ElytronToolMessages.msg.cmdFileSystemRealmHelpHeader().concat(ElytronToolMessages.msg.cmdLineActionsHelpHeader()),
                options,
                "",
                true);
    }

    @Override
    protected void warningHandler(String warning) {
        warningOccurred = true;
        if (! silentMode) {
            System.out.print("WARNING: ");
            System.out.println(warning);
        }
        if (summaryMode) {
            summaryString.append("WARNING: ");
            summaryString.append(warning);
            summaryString.append(LINE_SEPARATOR);
        }
    }

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
        summaryString.append("Found following users-roles combinations, null indicates missing required component:");
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
     * @param param The parameter to be obtained from the Descriptor object
     * @param descriptor The Descriptor object to be used
     * @return The value of the given parameter
     */
    private String getDescriptorParam(String param, Descriptor descriptor) {
        switch (param) {
            case USERS_FILE_PARAM: return descriptor.getUsersFile();
            case ROLES_FILE_PARAM: return descriptor.getRolesFile();
            case OUTPUT_LOCATION_PARAM: return descriptor.getOutputLocation();
            case FILESYSTEM_REALM_NAME_PARAM: return descriptor.getFileSystemRealmName();
            case SECURITY_DOMAIN_NAME_PARAM: return descriptor.getSecurityDomainName();
            default: return null;
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
                if (line.equals("")){
                    findMissingRequiredValuesAndSetValues(count.intValue(), descriptor);
                    copyAddResetDescriptor(descriptor);
                    count.getAndIncrement();
                } else {
                    // Since Windows URIs have a colon, only split at first occurrence
                    String[] parts = line.split(":", 2);
                    String option = parts[0];
                    String arg = parts[1];
                    switch (option) {
                        case USERS_FILE_PARAM:
                            descriptor.setUsersFile(arg);
                            break;
                        case ROLES_FILE_PARAM:
                            descriptor.setRolesFile(arg);
                            break;
                        case OUTPUT_LOCATION_PARAM:
                            descriptor.setOutputLocation(arg);
                            break;
                        case FILESYSTEM_REALM_NAME_PARAM:
                            descriptor.setFileSystemRealmName(arg);
                            break;
                        case SECURITY_DOMAIN_NAME_PARAM:
                            descriptor.setSecurityDomainName(arg);
                            break;
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
        if (descriptor.getUsersFile() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlock(count, "missing users-file"));
            missingRequiredValue = true;
        }
        if (descriptor.getRolesFile() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlock(count, "missing roles-file"));
            missingRequiredValue = true;
        }
        if (descriptor.getOutputLocation() == null) {
            warningHandler(ElytronToolMessages.msg.skippingDescriptorBlock(count, "missing output-location"));
            missingRequiredValue = true;
        }
        if (missingRequiredValue) {
            descriptor.reset();
        }
    }

    /**
     * Parses a uses or roles properties file to get the user mappings (users-password for users files
     * and users-roles for roles files).
     *
     * @param descriptor The descriptor class holding the information for this block
     * @param param The type of input file (either users-file or roles-file)
     * @param count The index of the current descriptor block
     * @return The String list of each user mapping in the file
     * @throws Exception Exception to be handled by Elytron Tool
     */
    private List<String> parseInputFile(Descriptor descriptor, String param, int count) throws Exception {
        List<String> entries = new ArrayList<>();
        String paramValue = getDescriptorParam(param, descriptor);
        boolean valueValid = true;
        Path path = null;
        if (paramValue == null) {
            warningHandler(ElytronToolMessages.msg.noValueFound(param));
            valueValid = false;
        } else {
            path = Paths.get(paramValue);
            if (!path.toFile().exists()) {
                if (descriptors.size() == 1) errorHandler(ElytronToolMessages.msg.fileNotFound(paramValue));
                warningHandler(ElytronToolMessages.msg.fileNotFound(paramValue).getMessage());
                warningHandler(ElytronToolMessages.msg.skippingDescriptorBlock(count, String.format("could not find file for %s", param)));
                valueValid = false;
            }
        }
        if (valueValid) {
            try (Stream<String> stream = Files.lines(path)) {
                stream.forEach(line -> {
                    if (line.startsWith("#$REALM_NAME=")) {
                        line = line.substring(line.indexOf("=") + 1);
                        line = line.substring(0, line.indexOf("$"));
                        descriptor.setRealmName(line);
                    } else if (!line.startsWith("#")){
                        entries.add(line);
                    }
                });
            }
        }
        return entries;
    }

    /**
     * Handles creating the Elytron filesystem-realm from the input arrays
     *
     * @throws Exception Exception to be handled by Elytron Tool
     */
    private void createFileSystemRealm() throws Exception {
        Security.addProvider(new WildFlyElytronProvider());
        for (int i = 0; i < descriptors.size(); i++) {
            Descriptor descriptor = descriptors.get(i);
            if (descriptor.getUsersFile() == null || descriptor.getRolesFile() == null || descriptor.getOutputLocation() == null) {
                continue;
            }
            List<String> usersList = parseInputFile(descriptor, USERS_FILE_PARAM, i + 1);
            List<String> rolesList = parseInputFile(descriptor, ROLES_FILE_PARAM, i + 1);
            if (usersList.isEmpty() || rolesList.isEmpty()) {
                descriptor.reset();
                continue;
            }
            FileSystemSecurityRealm newFileSystemRealm = new FileSystemSecurityRealm(Paths.get(descriptor.getOutputLocation()));
            Map<String, ArrayList<String>> usersMap = new HashMap<>();
            for (String userMapping : usersList) {
                String[] userStringSplit = userMapping.split("=");
                String user = userStringSplit[0].trim();
                String password;
                if (userStringSplit.length == 1) {
                    String message = String.format("No password was found for user %s", user);
                    warningHandler(message);
                    password = null;
                } else {
                    password = userStringSplit[1].trim();
                }
                ArrayList<String> userAttributes = new ArrayList<>();
                userAttributes.add(password);
                usersMap.put(user, userAttributes);
            }
            for (String rolesMapping : rolesList) {
                String[] rolesStringSplit = rolesMapping.split("=");
                String user = rolesStringSplit[0].trim();
                String[] roles = new String[]{};
                if (rolesStringSplit.length < 2) {
                    String message = String.format("No roles were found for user %s", user);
                    warningHandler(message);
                } else {
                    roles = rolesStringSplit[1].trim().split(",");
                }
                ArrayList<String> userAttributes = usersMap.get(user);
                if (userAttributes == null) {
                    String message = String.format("Roles were found for user %1$s, but user %1$s was not defined.", user);
                    warningHandler(message);
                    ArrayList<String> attributesWithEmptyPassword = new ArrayList<>();
                    attributesWithEmptyPassword.add(null);
                    attributesWithEmptyPassword.addAll(new ArrayList<>(Arrays.asList(roles)));
                    userAttributes = attributesWithEmptyPassword;
                    usersMap.put(user, userAttributes);
                } else {
                    userAttributes.addAll(Arrays.asList(roles));
                    usersMap.replace(user, userAttributes);
                }
                if (summaryMode) {
                    summaryString.append(String.format("Added roles: %s for user %s.", ArrayUtils.toString(roles), user));
                    summaryString.append(LINE_SEPARATOR);
                }
            }
            usersMap.forEach((key,value) -> {
                ModifiableRealmIdentity identity = newFileSystemRealm.getRealmIdentityForUpdate(new NamePrincipal(key));
                try {
                    identity.create();
                    MapAttributes attributes = new MapAttributes();
                    attributes.addAll("roles", value.subList(1, value.size()));
                    identity.setAttributes(attributes);
                    String password = value.get(0);
                    if (password != null) {
                        byte[] hashed = ByteIterator.ofBytes(password.getBytes(StandardCharsets.UTF_8)).asUtf8String().hexDecode().drain();
                        PasswordSpec passwordSpec = new DigestPasswordSpec(key, descriptor.getRealmName(), hashed);
                        PasswordFactory factory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5);
                        DigestPassword digestPassword = (DigestPassword) factory.generatePassword(passwordSpec);
                        identity.setCredentials(Collections.singleton(new PasswordCredential(digestPassword)));
                    }
                    identity.dispose();
                } catch (NullPointerException e) {
                    warningHandler(String.format("Could not read realm name from the users file"));
                } catch (Exception e) {
                    warningHandler(String.format("Could not create realm for user %s due to error: ", key) + e.getMessage());
                }
            });
        }
    }

    /**
     * Creates the script/commands the user must run for Elytron to recognize
     * and use the new filesystem-realm
     */
    private void createWildFlyScript() throws Exception {
        for (Descriptor descriptor : descriptors) {
            String usersFile = descriptor.getUsersFile();
            if (descriptor.getUsersFile() == null || descriptor.getRolesFile() == null || descriptor.getOutputLocation() == null) {
                continue;
            }
            String fileSystemRealmName = descriptor.getFileSystemRealmName();
            if (fileSystemRealmName == null || fileSystemRealmName.isEmpty()) {
                warningHandler(String.format("No name provided for filesystem-realm, using default filesystem-realm name for %s.", usersFile));
                descriptor.setFileSystemRealmName(DEFAULT_FILESYSTEM_REALM_NAME);
                fileSystemRealmName = DEFAULT_FILESYSTEM_REALM_NAME;
            }
            String outputLocation = descriptor.getOutputLocation();
            String securityDomainName = descriptor.getSecurityDomainName();

            String createScriptCheck = "";
            if (Paths.get(String.format("%s.sh", fileSystemRealmName)).toFile().exists()) {
                createScriptCheck = prompt(
                        false,
                        null,
                        false,
                        ElytronToolMessages.msg.shouldFileBeOverwritten(String.format("%s.sh", fileSystemRealmName))
                );
            }
            String fullOutputPath;
            if (outputLocation.startsWith(".")) {
                fullOutputPath = Paths.get(outputLocation.substring(2, outputLocation.length())).toAbsolutePath().toString();
            } else {
                fullOutputPath = Paths.get(outputLocation).toAbsolutePath().toString();
            }

            if (summaryMode) {
                summaryString.append(String.format("Configured script for WildFly named %s.sh at %s.", fileSystemRealmName, fullOutputPath));
                summaryString.append(LINE_SEPARATOR);
                summaryString.append("The script is using the following names:");
                summaryString.append(LINE_SEPARATOR);
                summaryString.append(String.format("Name of filesystem-realm: %s", fileSystemRealmName));
                summaryString.append(LINE_SEPARATOR);
            }

            if (securityDomainName != null && !securityDomainName.isEmpty()) {
                if (summaryMode) {
                    summaryString.append(String.format("Name of security-domain: %s",securityDomainName));
                    summaryString.append(LINE_SEPARATOR);
                }
            } else {
                warningHandler(String.format("No name provided for security-domain, using default security-domain name for %s.", usersFile));
                securityDomainName = DEFAULT_SECURITY_DOMAIN_NAME;
            }

            List<String> scriptLines = Arrays.asList(
                String.format("/subsystem=elytron/filesystem-realm=%s:add(path=%s)", fileSystemRealmName, fullOutputPath),
                String.format("/subsystem=elytron/security-domain=%1$s:add(realms=[{realm=%2$s}],default-realm=%2$s,permission-mapper=default-permission-mapper)", securityDomainName, fileSystemRealmName)
            );

            if (!"y".equals(createScriptCheck) && !"yes".equals(createScriptCheck)) {
                Files.write(Paths.get(String.format("%s/%s.sh", outputLocation, fileSystemRealmName)), scriptLines, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            } else {
                Files.write(Paths.get(String.format("%s/%s.sh", outputLocation, fileSystemRealmName)), scriptLines, StandardOpenOption.APPEND);
            }
        }
    }
}
