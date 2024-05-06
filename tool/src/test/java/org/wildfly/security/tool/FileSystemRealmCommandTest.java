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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.tool.Params.FILE_SEPARATOR;
import static org.wildfly.security.tool.Params.LINE_SEPARATOR;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * Tests relating to FileSystemRealm conversion command
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public class FileSystemRealmCommandTest extends AbstractCommandTest {
    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private static final int EXPECTED_OK = 0;
    private static final int EXPECTED_WARNING = 1;
    private static final int EXPECTED_ERROR = 7;

    private static final String RELATIVE_BASE_DIR = "./target/test-classes/filesystem-realm/";
    private static String ABSOLUTE_BASE_DIR = "";
    private static final String RELATIVE_BASE_DIR_USERS = RELATIVE_BASE_DIR + "users/";
    private static final String RELATIVE_BASE_DIR_ROLES = RELATIVE_BASE_DIR + "roles/";
    private static String ABSOLUTE_BASE_DIR_USERS = "";
    private static String ABSOLUTE_BASE_DIR_ROLES = "";
    private static String[] OUTPUT_LOCATIONS_CLI = new String[13];
    private static String[] OUTPUT_LOCATIONS_BULK = new String[11];

    private static final String ELYTRON_PASSWORD = "testPasswordElytron";
    private static final String JAVAJOE_PASSWORD = "testPasswordJavaJoe";
    private static final String ELYTRON_USER = "elytron";
    private static final String JAVAJOE_USER = "javajoe";
    private static final String NOTAUSER_USER = "notauser";
    private static final String NOPASSUSER_USER = "nopassuser";
    private static final ArrayList<String> ELYTRON_SINGLE_ROLE = new ArrayList<>(Arrays.asList("role1"));
    private static final ArrayList<String> ELYTRON_MULTIPLE_ROLES = new ArrayList<>(Arrays.asList("role1", "role2", "role3"));
    private static final ArrayList<String> JAVAJOE_NO_ROLE = new ArrayList<>();
    private static final ArrayList<String> JAVAJOE_SINGLE_ROLE = new ArrayList<>(Arrays.asList("role2"));
    private static final ArrayList<String> JAVAJOE_MULTIPLE_ROLES = new ArrayList<>(Arrays.asList("role1", "role3", "role4", "role5"));
    private static final ArrayList<String> NOTAUSER_ROLES = new ArrayList<>(Arrays.asList("role2", "role3"));
    private static final ArrayList<String> NOPASSUSER_MULTIPLE_ROLES = new ArrayList<>(Arrays.asList("role1", "role2", "role3"));

    private static final String[] FILE_SYSTEM_REALM_SCRIPT_OUTPUT_PARTS = new String[]{"/subsystem=elytron/filesystem-realm=", ":add(path=", ")"};
    private static final String[] SECURITY_DOMAIN_SCRIPT_OUTPUT_PARTS = new String[]{"/subsystem=elytron/security-domain=", ":add(realms=[{realm=", "}],default-realm=", ",permission-mapper=default-permission-mapper)"};
    private static final String DEFAULT_FILESYSTEM_REALM_NAME = "converted-properties-filesystem-realm";
    private static final String DEFAULT_SECURITY_DOMAIN_NAME = "converted-properties-security-domain";

    @Override
    protected String getCommandType() {
        return FileSystemRealmCommand.FILE_SYSTEM_REALM_COMMAND;
    }

    private void run(String usersFile, String rolesFile, String outputLocation, String fileSystemRealmName, String securityDomainName, int expectedStatus) {
        runCommandSilent(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, expectedStatus);
    }

    private void run(String bulkConvertFile, int expectedStatus) {
        runCommandSilent(bulkConvertFile, expectedStatus);
    }

    private void runCommand(String usersFile, String rolesFile, String outputLocation, String fileSystemRealmName, String securityDomainName, int expectedStatus) {
        String[] requiredArgs;
        requiredArgs = new String[]{"--users-file", usersFile, "--roles-file", rolesFile, "--output-location", outputLocation, "-f", fileSystemRealmName, "-s", securityDomainName};
        executeCommandAndCheckStatus(requiredArgs, expectedStatus);
    }

    private void runCommand(String bulkConvertFile, int expectedStatus) {
        String[] requiredArgs;
        requiredArgs = new String[]{"--bulk-convert", bulkConvertFile};
        executeCommandAndCheckStatus(requiredArgs, expectedStatus);
    }

    private void runCommandSilent(String usersFile, String rolesFile, String outputLocation, String fileSystemRealmName, String securityDomainName, int expectedStatus) {
        String[] requiredArgsSilent;
        requiredArgsSilent = new String[]{"--users-file", usersFile, "--roles-file", rolesFile, "--output-location", outputLocation, "-f", fileSystemRealmName, "-s", securityDomainName, "--silent"};
        executeCommandAndCheckStatus(requiredArgsSilent, expectedStatus);
    }

    private void runCommandSilent(String bulkConvertFile, int expectedStatus) {
        String[] requiredArgsSilent;
        requiredArgsSilent = new String[]{"--bulk-convert", bulkConvertFile, "--silent"};
        executeCommandAndCheckStatus(requiredArgsSilent, expectedStatus);
    }

    private void runCommandSummary(String usersFile, String rolesFile, String outputLocation, String fileSystemRealmName, String securityDomainName, int expectedStatus) {
        String[] requiredArgsSummary;
        requiredArgsSummary = new String[]{"--users-file", usersFile, "--roles-file", rolesFile, "--output-location", outputLocation, "-f", fileSystemRealmName, "-s", securityDomainName, "--summary"};
        executeCommandAndCheckStatus(requiredArgsSummary, expectedStatus);
    }

    private void runCommandSummary(String bulkConvertFile, int expectedStatus) {
        String[] requiredArgsSummary;
        requiredArgsSummary = new String[]{"--bulk-convert", bulkConvertFile, "--summary"};
        executeCommandAndCheckStatus(requiredArgsSummary, expectedStatus);
    }

    private void runCommandSilentSummary(String usersFile, String rolesFile, String outputLocation, String fileSystemRealmName, String securityDomainName, int expectedStatus) {
        String[] requiredArgsSilentSummary;
        requiredArgsSilentSummary = new String[]{"--users-file", usersFile, "--roles-file", rolesFile, "--output-location", outputLocation, "-f", fileSystemRealmName, "-s", securityDomainName, "--silent", "--summary"};
        executeCommandAndCheckStatus(requiredArgsSilentSummary, expectedStatus);
    }

    private void runCommandSilentSummary(String bulkConvertFile, int expectedStatus) {
        String[] requiredArgsSilentSummary;
        requiredArgsSilentSummary = new String[]{"--bulk-convert", bulkConvertFile, "--silent", "--summary"};
        executeCommandAndCheckStatus(requiredArgsSilentSummary, expectedStatus);
    }

    private void runCommandRequiredArgsWithAllSilentSummaryOptions(String usersFile, String rolesFile, String outputLocation, String fileSystemRealmName, String securityDomainName, int expectedStatus) {
        runCommandSilent(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, expectedStatus);
        runCommand(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, expectedStatus);
        runCommandSilentSummary(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, expectedStatus);
        runCommandSummary(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, expectedStatus);
    }

    private void runCommandRequiredArgsWithAllSilentSummaryOptions(String bulkConvertFile, int expectedStatus) {
        runCommandSilent(bulkConvertFile, expectedStatus);
        runCommand(bulkConvertFile, expectedStatus);
        runCommandSilentSummary(bulkConvertFile, expectedStatus);
        runCommandSummary(bulkConvertFile, expectedStatus);
    }

    private void checkFileSystemRealmCreatedSuccessfully(Map<String, ArrayList<String>> userMap, String outputLocation) throws Exception {
        Set<String> names = userMap.keySet();
        for (String name : names) {
            FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(Paths.get(outputLocation));
            ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal(name));
            assertTrue(existingIdentity.exists());

            if (name.equals("elytron")) {
                if (existingIdentity.getCredential(PasswordCredential.class) != null) {
                    assertTrue(existingIdentity.verifyEvidence(new PasswordGuessEvidence(ELYTRON_PASSWORD.toCharArray())));
                }
            } else if (name.equals("javajoe")) {
                if (existingIdentity.getCredential(PasswordCredential.class) != null) {
                    assertTrue(existingIdentity.verifyEvidence(new PasswordGuessEvidence(JAVAJOE_PASSWORD.toCharArray())));
                }
            }

            AuthorizationIdentity authorizationIdentity = existingIdentity.getAuthorizationIdentity();
            Attributes attributes = authorizationIdentity.getAttributes();
            existingIdentity.dispose();

            assertTrue(userMap.get(name).containsAll(attributes.get("roles")));
        }
    }

    private void checkMultipleFileSystemRealmCreatedSuccessfully(Map<String, Map<String, ArrayList<String>>> userMaps, Map<String, String[]> optionalParamsMap) throws Exception {
        for (String outputLocation : userMaps.keySet()) {
            checkFileSystemRealmCreatedSuccessfully(userMaps.get(outputLocation), outputLocation);
            String[] optionalParams = optionalParamsMap.get(outputLocation);
            if (outputLocation.startsWith(".")) {
                compareScriptOutput(optionalParams[0], optionalParams[1], Paths.get(outputLocation.substring(2, outputLocation.length())).toAbsolutePath().toString());
            } else {
                compareScriptOutput(optionalParams[0], optionalParams[1], outputLocation);
            }
        }
    }

    private void compareScriptOutput(String fileSystemRealmName, String securityDomainName, String outputLocation) throws Exception {
        List<String> scriptLines = Files.readAllLines(Paths.get(outputLocation, fileSystemRealmName + ".sh"));

        StringBuilder expectedFileSystemRealmScript = new StringBuilder();
        expectedFileSystemRealmScript.append(FILE_SYSTEM_REALM_SCRIPT_OUTPUT_PARTS[0]);
        expectedFileSystemRealmScript.append(fileSystemRealmName);
        expectedFileSystemRealmScript.append(FILE_SYSTEM_REALM_SCRIPT_OUTPUT_PARTS[1]);
        expectedFileSystemRealmScript.append(outputLocation);
        expectedFileSystemRealmScript.append(FILE_SYSTEM_REALM_SCRIPT_OUTPUT_PARTS[2]);

        StringBuilder expectedSecurityDomainScript = new StringBuilder();
        expectedSecurityDomainScript.append(SECURITY_DOMAIN_SCRIPT_OUTPUT_PARTS[0]);
        expectedSecurityDomainScript.append(securityDomainName);
        expectedSecurityDomainScript.append(SECURITY_DOMAIN_SCRIPT_OUTPUT_PARTS[1]);
        expectedSecurityDomainScript.append(fileSystemRealmName);
        expectedSecurityDomainScript.append(SECURITY_DOMAIN_SCRIPT_OUTPUT_PARTS[2]);
        expectedSecurityDomainScript.append(fileSystemRealmName);
        expectedSecurityDomainScript.append(SECURITY_DOMAIN_SCRIPT_OUTPUT_PARTS[3]);

        assertEquals(scriptLines.get(0), expectedFileSystemRealmScript.toString());
        assertEquals(scriptLines.get(1), expectedSecurityDomainScript.toString());
    }

    @BeforeClass
    public static void getAbsolutePaths() throws Exception {
        ABSOLUTE_BASE_DIR = Paths.get(FileSystemRealmCommandTest.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                .toAbsolutePath()
                + FILE_SEPARATOR
                + "filesystem-realm"
                + FILE_SEPARATOR;
        ABSOLUTE_BASE_DIR_USERS = ABSOLUTE_BASE_DIR + "users" + FILE_SEPARATOR;
        ABSOLUTE_BASE_DIR_ROLES = ABSOLUTE_BASE_DIR + "roles" + FILE_SEPARATOR;
        OUTPUT_LOCATIONS_CLI[0] = RELATIVE_BASE_DIR + "output-1";
        OUTPUT_LOCATIONS_CLI[1] = ABSOLUTE_BASE_DIR + "output-2";
        OUTPUT_LOCATIONS_CLI[2] = RELATIVE_BASE_DIR + "output-3";
        OUTPUT_LOCATIONS_CLI[3] = ABSOLUTE_BASE_DIR + "output-4";
        OUTPUT_LOCATIONS_CLI[4] = RELATIVE_BASE_DIR + "output-5";
        OUTPUT_LOCATIONS_CLI[5] = ABSOLUTE_BASE_DIR + "output-6";
        OUTPUT_LOCATIONS_CLI[6] = ABSOLUTE_BASE_DIR + "output-7";
        OUTPUT_LOCATIONS_CLI[7] = ABSOLUTE_BASE_DIR + "wrong-output-1";
        OUTPUT_LOCATIONS_CLI[8] = ABSOLUTE_BASE_DIR + "wrong-output-2";
        OUTPUT_LOCATIONS_CLI[9] = ABSOLUTE_BASE_DIR + "wrong-output-3";
        OUTPUT_LOCATIONS_CLI[10] = ABSOLUTE_BASE_DIR + "wrong-output-4";
        OUTPUT_LOCATIONS_CLI[11] = ABSOLUTE_BASE_DIR + "wrong-output-5";
        OUTPUT_LOCATIONS_CLI[12] = ABSOLUTE_BASE_DIR + "wrong-output-6";
        OUTPUT_LOCATIONS_BULK[0] = RELATIVE_BASE_DIR + "output-1-bulk";
        OUTPUT_LOCATIONS_BULK[1] = RELATIVE_BASE_DIR + "output-2-bulk";
        OUTPUT_LOCATIONS_BULK[2] = RELATIVE_BASE_DIR + "output-3-bulk";
        OUTPUT_LOCATIONS_BULK[3] = RELATIVE_BASE_DIR + "output-4-bulk";
        OUTPUT_LOCATIONS_BULK[4] = ABSOLUTE_BASE_DIR + "output-5-bulk";
        OUTPUT_LOCATIONS_BULK[5] = ABSOLUTE_BASE_DIR + "output-6-bulk";
        OUTPUT_LOCATIONS_BULK[6] = ABSOLUTE_BASE_DIR + "output-4-bulk-wrong-1";
        OUTPUT_LOCATIONS_BULK[7] = ABSOLUTE_BASE_DIR + "output-1-bulk-wrong-2";
        OUTPUT_LOCATIONS_BULK[8] = ABSOLUTE_BASE_DIR + "output-2-bulk-wrong-2";
        OUTPUT_LOCATIONS_BULK[9] = ABSOLUTE_BASE_DIR + "output-3-bulk-wrong-2";
        OUTPUT_LOCATIONS_BULK[10] = ABSOLUTE_BASE_DIR + "output-4-bulk-wrong-2";
    }

    @BeforeClass
    public static void createAbsoluteDescriptorFile() throws Exception {
        String fileText = "";
        fileText = fileText + "users-file:" + ABSOLUTE_BASE_DIR_USERS + "users-5.properties";
        fileText += LINE_SEPARATOR;
        fileText = fileText + "roles-file:" + ABSOLUTE_BASE_DIR_ROLES + "roles-5.properties";
        fileText += LINE_SEPARATOR;
        fileText += "output-location:" + ABSOLUTE_BASE_DIR + "output-5-bulk";
        fileText += LINE_SEPARATOR;
        fileText += "filesystem-realm-name:nameOfFileSystemRealm5";
        fileText += LINE_SEPARATOR;
        fileText += "security-domain-name:nameOfSecurityDomain5";
        fileText += LINE_SEPARATOR;
        fileText += LINE_SEPARATOR;
        fileText = fileText + "users-file:" + ABSOLUTE_BASE_DIR_USERS + "users-6.properties";
        fileText += LINE_SEPARATOR;
        fileText = fileText + "roles-file:" + ABSOLUTE_BASE_DIR_ROLES + "roles-6.properties";
        fileText += LINE_SEPARATOR;
        fileText = fileText + "output-location:" + ABSOLUTE_BASE_DIR + "output-6-bulk";
        fileText += LINE_SEPARATOR;
        fileText += "filesystem-realm-name:nameOfFileSystemRealm6";
        fileText += LINE_SEPARATOR;
        fileText += "security-domain-name:nameOfSecurityDomain6";
        fileText += LINE_SEPARATOR;
        Files.write(Paths.get(RELATIVE_BASE_DIR + "descriptor-file-2"), fileText.getBytes(), StandardOpenOption.CREATE);
    }

    @AfterClass
    public static void cleanup() throws Exception {
        for (String outputLocation : OUTPUT_LOCATIONS_CLI) {
            Path outputPath = Paths.get(outputLocation);
            if (outputPath.toFile().exists()) {
                Files.walk(outputPath).sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
            }
        }
        for (String outputLocation : OUTPUT_LOCATIONS_BULK) {
            Path outputPath = Paths.get(outputLocation);
            if (outputPath.toFile().exists()) {
                Files.walk(outputPath).sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
            }
        }
        new File(RELATIVE_BASE_DIR + "descriptor-file-2").delete();
    }

    @Test
    public void testHelp() {
        String[] args = new String[]{"--help"};
        executeCommandAndCheckStatus(args);
    }

    @Test
    public void testSingleUserSingleRole() throws Exception {
        String usersFile = RELATIVE_BASE_DIR_USERS + "users-1.properties";
        String rolesFile = RELATIVE_BASE_DIR_ROLES + "roles-1.properties";
        String outputLocation = RELATIVE_BASE_DIR + "output-1";
        String fileSystemRealmName = "single-user-single-role-fs";
        String securityDomainName = "single-user-single-role-sd";

        Map<String, ArrayList<String>> userMap = new HashMap<>();
        userMap.put(ELYTRON_USER, ELYTRON_SINGLE_ROLE);

        run(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, EXPECTED_OK);
        checkFileSystemRealmCreatedSuccessfully(userMap, outputLocation);
        compareScriptOutput(fileSystemRealmName, securityDomainName, Paths.get(outputLocation.substring(2, outputLocation.length())).toAbsolutePath().toString());
    }

    @Test
    public void testSingleUserMultipleRoles() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "users-2.properties";
        String rolesFile = ABSOLUTE_BASE_DIR_ROLES + "roles-2.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "output-2";
        String fileSystemRealmName = "";
        String securityDomainName = "";

        Map<String, ArrayList<String>> userMap = new HashMap<>();
        userMap.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);

        run(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, EXPECTED_WARNING);
        checkFileSystemRealmCreatedSuccessfully(userMap, outputLocation);
        compareScriptOutput(DEFAULT_FILESYSTEM_REALM_NAME, DEFAULT_SECURITY_DOMAIN_NAME, outputLocation);
    }

    @Test
    public void testMultipleUsersSingleRole() throws Exception {
        String usersFile = RELATIVE_BASE_DIR_USERS + "users-3.properties";
        String rolesFile = ABSOLUTE_BASE_DIR_ROLES + "roles-3.properties";
        String outputLocation = RELATIVE_BASE_DIR + "output-3";
        String fileSystemRealmName = "";
        String securityDomainName = "multiple-users-single-role-sd";

        Map<String, ArrayList<String>> userMap = new HashMap<>();
        userMap.put(ELYTRON_USER, ELYTRON_SINGLE_ROLE);
        userMap.put(JAVAJOE_USER, JAVAJOE_SINGLE_ROLE);

        run(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, EXPECTED_WARNING);
        checkFileSystemRealmCreatedSuccessfully(userMap, outputLocation);
        compareScriptOutput(DEFAULT_FILESYSTEM_REALM_NAME, securityDomainName, Paths.get(outputLocation.substring(2, outputLocation.length())).toAbsolutePath().toString());
    }

    @Test
    public void testMultipleUsersMultipleRoles() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "users-4.properties";
        String rolesFile = RELATIVE_BASE_DIR_ROLES + "roles-4.properties";
        String outputLocation = RELATIVE_BASE_DIR + "output-4";
        String fileSystemRealmName = "multiple-users-multiple-roles-fs";
        String securityDomainName = "multiple-users-multiple-roles-sd";

        Map<String, ArrayList<String>> userMap = new HashMap<>();
        userMap.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        userMap.put(JAVAJOE_USER, JAVAJOE_MULTIPLE_ROLES);

        run(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, EXPECTED_OK);
        checkFileSystemRealmCreatedSuccessfully(userMap, outputLocation);
        compareScriptOutput(fileSystemRealmName, securityDomainName, Paths.get(outputLocation.substring(2, outputLocation.length())).toAbsolutePath().toString());
    }

    @Test
    public void testMultipleUsersMultipleRolesExtraUserInRoles() throws Exception {
        String usersFile = RELATIVE_BASE_DIR_USERS + "users-5.properties";
        String rolesFile = RELATIVE_BASE_DIR_ROLES + "roles-5.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "output-5";
        String fileSystemRealmName = "";
        String securityDomainName = "";

        Map<String, ArrayList<String>> userMap = new HashMap<>();
        userMap.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        userMap.put(NOTAUSER_USER, NOTAUSER_ROLES);
        userMap.put(JAVAJOE_USER, JAVAJOE_MULTIPLE_ROLES);

        run(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, EXPECTED_WARNING);
        checkFileSystemRealmCreatedSuccessfully(userMap, outputLocation);
        compareScriptOutput(DEFAULT_FILESYSTEM_REALM_NAME, DEFAULT_SECURITY_DOMAIN_NAME, outputLocation);
    }

    @Test
    public void testMultipleUsersMultipleRolesUserWithNoRoles() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "users-6.properties";
        String rolesFile = RELATIVE_BASE_DIR_ROLES + "roles-6.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "output-6";
        String fileSystemRealmName = "multiple-users-multiple-roles-user-no-role-fs";
        String securityDomainName = "";

        Map<String, ArrayList<String>> userMap = new HashMap<>();
        userMap.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        userMap.put(JAVAJOE_USER, JAVAJOE_NO_ROLE);

        run(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, EXPECTED_WARNING);
        checkFileSystemRealmCreatedSuccessfully(userMap, outputLocation);
        compareScriptOutput(fileSystemRealmName, DEFAULT_SECURITY_DOMAIN_NAME, outputLocation);
    }

    @Test
    public void noPassword() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "users-7.properties";
        String rolesFile = RELATIVE_BASE_DIR_ROLES + "roles-7.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "output-7";
        String fileSystemRealmName = "";
        String securityDomainName = "";

        Map<String, ArrayList<String>> userMap = new HashMap<>();
        userMap.put(NOPASSUSER_USER, NOPASSUSER_MULTIPLE_ROLES);

        run(usersFile, rolesFile, outputLocation, fileSystemRealmName, securityDomainName, EXPECTED_WARNING);
        checkFileSystemRealmCreatedSuccessfully(userMap, outputLocation);
        compareScriptOutput(DEFAULT_FILESYSTEM_REALM_NAME, DEFAULT_SECURITY_DOMAIN_NAME, outputLocation);
    }

    @Test
    public void testNoUsersFile() throws Exception {
        exception.expect(RuntimeException.class);
        exception.expectMessage(ElytronToolMessages.msg.missingUsersFile().getMessage());

        String rolesFile = RELATIVE_BASE_DIR_ROLES + "roles-8.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "output-8";

        String[] requiredArgs;
        requiredArgs = new String[]{"--roles-file", rolesFile, "--output-location", outputLocation, "--summary"};
        executeCommandAndCheckStatus(requiredArgs, EXPECTED_ERROR);
    }

    @Test
    public void testNoRolesFile() throws Exception {
        exception.expect(RuntimeException.class);
        exception.expectMessage(ElytronToolMessages.msg.missingRolesFile().getMessage());

        String usersFile = ABSOLUTE_BASE_DIR_USERS + "users-9.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "output-9";

        String[] requiredArgs;
        requiredArgs = new String[]{"--users-file", usersFile, "--output-location", outputLocation, "--summary"};
        executeCommandAndCheckStatus(requiredArgs, EXPECTED_ERROR);
    }

    @Test
    public void testNoOutputLocation() throws Exception {
        exception.expect(RuntimeException.class);
        exception.expectMessage(ElytronToolMessages.msg.missingOutputLocation().getMessage());

        String usersFile = ABSOLUTE_BASE_DIR_USERS + "users-10.properties";
        String rolesFile = RELATIVE_BASE_DIR_ROLES + "roles-10.properties";

        String[] requiredArgs;
        requiredArgs = new String[]{"--users-file", usersFile, "--roles-file", rolesFile, "--summary"};
        executeCommandAndCheckStatus(requiredArgs, EXPECTED_ERROR);
    }

    @Test
    public void testMalformedUsersFile() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "wrong-users-1.properties";
        String rolesFile = ABSOLUTE_BASE_DIR_ROLES + "roles-1.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "wrong-output-1";

        String[] args = new String[]{"-u", usersFile, "-r", rolesFile, "-o", outputLocation};
        executeCommandAndCheckStatus(args, EXPECTED_WARNING);
    }

    @Test
    public void testMalformedUsersFileSilent() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "wrong-users-1.properties";
        String rolesFile = ABSOLUTE_BASE_DIR_ROLES + "roles-1.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "wrong-output-2";

        String[] args = new String[]{"--silent", "-u", usersFile, "-r", rolesFile, "-o", outputLocation};
        String output = executeCommandAndCheckStatusAndGetOutput(args, EXPECTED_WARNING);
        assertEquals("silent command should not return any output", "", output);
    }

    @Test
    public void testNoRealmUsersFile() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "wrong-users-2.properties";
        String rolesFile = ABSOLUTE_BASE_DIR_ROLES + "roles-1.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "wrong-output-3";

        String[] args = new String[]{"-u", usersFile, "-r", rolesFile, "-o", outputLocation};
        executeCommandAndCheckStatus(args, EXPECTED_WARNING);
    }

    @Test
    public void testNoRealmUsersFileSilent() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "wrong-users-2.properties";
        String rolesFile = ABSOLUTE_BASE_DIR_ROLES + "roles-1.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "wrong-output-4";

        String[] args = new String[]{"--silent", "-u", usersFile, "-r", rolesFile, "-o", outputLocation};
        String output = executeCommandAndCheckStatusAndGetOutput(args, EXPECTED_WARNING);
        assertEquals("silent command should not return any output", "", output);
    }

    @Test
    public void testWrongUserInRolesFile() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "users-1.properties";
        String rolesFile = ABSOLUTE_BASE_DIR_ROLES + "wrong-roles-1.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "wrong-output-5";

        String[] args = new String[]{"-u", usersFile, "-r", rolesFile, "-o", outputLocation};
        executeCommandAndCheckStatus(args, EXPECTED_WARNING);
    }

    @Test
    public void testWrongUserInRolesFileSilent() throws Exception {
        String usersFile = ABSOLUTE_BASE_DIR_USERS + "users-1.properties";
        String rolesFile = ABSOLUTE_BASE_DIR_ROLES + "wrong-roles-1.properties";
        String outputLocation = ABSOLUTE_BASE_DIR + "wrong-output-6";

        String[] args = new String[]{"--silent", "-u", usersFile, "-r", rolesFile, "-o", outputLocation};
        String output = executeCommandAndCheckStatusAndGetOutput(args, EXPECTED_WARNING);
        assertEquals("silent command should not return any output", "", output);
    }

    @Test
    public void testBulkFileRelativePath() throws Exception {
        String descriptorFile = RELATIVE_BASE_DIR + "descriptor-file-1";

        Map<String, ArrayList<String>> userMap1 = new HashMap<>();
        userMap1.put(ELYTRON_USER, ELYTRON_SINGLE_ROLE);
        Map<String, ArrayList<String>> userMap2 = new HashMap<>();
        userMap2.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        Map<String, ArrayList<String>> userMap3 = new HashMap<>();
        userMap3.put(ELYTRON_USER, ELYTRON_SINGLE_ROLE);
        userMap3.put(JAVAJOE_USER, JAVAJOE_SINGLE_ROLE);
        Map<String, ArrayList<String>> userMap4 = new HashMap<>();
        userMap4.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        userMap4.put(JAVAJOE_USER, JAVAJOE_MULTIPLE_ROLES);

        Map<String, Map<String, ArrayList<String>>> userMaps = new HashMap<>();
        userMaps.put(OUTPUT_LOCATIONS_BULK[0], userMap1);
        userMaps.put(OUTPUT_LOCATIONS_BULK[1], userMap2);
        userMaps.put(OUTPUT_LOCATIONS_BULK[2], userMap3);
        userMaps.put(OUTPUT_LOCATIONS_BULK[3], userMap4);

        Map<String, String[]> optionalParamsMap = new HashMap<>();
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[0], new String[]{"nameOfFileSystemRealm1", "nameOfSecurityDomain1"});
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[1], new String[]{"nameOfFileSystemRealm2", "nameOfSecurityDomain2"});
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[2], new String[]{DEFAULT_FILESYSTEM_REALM_NAME, DEFAULT_SECURITY_DOMAIN_NAME});
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[3], new String[]{"nameOfFileSystemRealm4", "nameOfSecurityDomain4"});

        runCommandSummary(descriptorFile, EXPECTED_WARNING);
        checkMultipleFileSystemRealmCreatedSuccessfully(userMaps, optionalParamsMap);
    }

    @Test
    public void testBulkFileAbsolutePath() throws Exception {
        String descriptorFile = ABSOLUTE_BASE_DIR + "descriptor-file-2";

        Map<String, ArrayList<String>> userMap5 = new HashMap<>();
        userMap5.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        userMap5.put(NOTAUSER_USER, NOTAUSER_ROLES);
        userMap5.put(JAVAJOE_USER, JAVAJOE_MULTIPLE_ROLES);
        Map<String, ArrayList<String>> userMap6 = new HashMap<>();
        userMap6.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        userMap6.put(JAVAJOE_USER, JAVAJOE_NO_ROLE);

        Map<String, Map<String, ArrayList<String>>> userMaps = new HashMap<>();
        userMaps.put(OUTPUT_LOCATIONS_BULK[4], userMap5);
        userMaps.put(OUTPUT_LOCATIONS_BULK[5], userMap6);

        Map<String, String[]> optionalParamsMap = new HashMap<>();
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[4], new String[]{"nameOfFileSystemRealm5", "nameOfSecurityDomain5"});
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[5], new String[]{"nameOfFileSystemRealm6", "nameOfSecurityDomain6"});

        run(descriptorFile, EXPECTED_WARNING);
        checkMultipleFileSystemRealmCreatedSuccessfully(userMaps, optionalParamsMap);
    }

    @Test
    public void testMalformedBulkFile() throws Exception {
        String descriptionFile = ABSOLUTE_BASE_DIR + "wrong-descriptor-file-1";

        Map<String, ArrayList<String>> userMap4 = new HashMap<>(2);
        userMap4.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        userMap4.put(JAVAJOE_USER, JAVAJOE_MULTIPLE_ROLES);

        Map<String, Map<String, ArrayList<String>>> userMaps = new HashMap<>(1);
        userMaps.put(OUTPUT_LOCATIONS_BULK[6], userMap4);

        Map<String, String[]> optionalParamsMap = new HashMap<>();
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[6], new String[]{"nameOfFileSystemRealm6", "nameOfSecurityDomain6"});

        run(descriptionFile, EXPECTED_WARNING);
        checkMultipleFileSystemRealmCreatedSuccessfully(userMaps, optionalParamsMap);
    }

    @Test
    public void testBulkFileContainingMalformedUsersFile() throws Exception {
        String descriptorFile = RELATIVE_BASE_DIR + "wrong-descriptor-file-2";

        Map<String, ArrayList<String>> userMap1 = new HashMap<>();
        userMap1.put(ELYTRON_USER, ELYTRON_SINGLE_ROLE);
        Map<String, ArrayList<String>> userMap2 = new HashMap<>();
        userMap2.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        Map<String, ArrayList<String>> userMap3 = new HashMap<>();
        userMap3.put(ELYTRON_USER, ELYTRON_SINGLE_ROLE);
        userMap3.put(JAVAJOE_USER, JAVAJOE_SINGLE_ROLE);
        Map<String, ArrayList<String>> userMap4 = new HashMap<>();
        userMap4.put(ELYTRON_USER, ELYTRON_MULTIPLE_ROLES);
        userMap4.put(JAVAJOE_USER, JAVAJOE_MULTIPLE_ROLES);

        Map<String, Map<String, ArrayList<String>>> userMaps = new HashMap<>();
        userMaps.put(OUTPUT_LOCATIONS_BULK[7], userMap1);
        userMaps.put(OUTPUT_LOCATIONS_BULK[8], userMap2);
        userMaps.put(OUTPUT_LOCATIONS_BULK[9], userMap3);
        userMaps.put(OUTPUT_LOCATIONS_BULK[10], userMap4);

        Map<String, String[]> optionalParamsMap = new HashMap<>();
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[7], new String[]{"nameOfFileSystemRealm1", "nameOfSecurityDomain1"});
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[8], new String[]{"nameOfFileSystemRealm2", "nameOfSecurityDomain2"});
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[9], new String[]{DEFAULT_FILESYSTEM_REALM_NAME, DEFAULT_SECURITY_DOMAIN_NAME});
        optionalParamsMap.put(OUTPUT_LOCATIONS_BULK[10], new String[]{"nameOfFileSystemRealm4", "nameOfSecurityDomain4"});

        run(descriptorFile, EXPECTED_WARNING);
        checkMultipleFileSystemRealmCreatedSuccessfully(userMaps, optionalParamsMap);
    }
}
