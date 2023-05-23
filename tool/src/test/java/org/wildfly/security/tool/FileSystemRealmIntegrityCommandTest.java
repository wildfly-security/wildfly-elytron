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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.tool.Command.GENERAL_CONFIGURATION_ERROR;
import static org.wildfly.security.tool.Command.GENERAL_CONFIGURATION_WARNING;
import static org.wildfly.security.tool.ElytronTool.ElytronToolExitStatus_OK;
import static org.wildfly.security.tool.FileSystemRealmIntegrityCommand.FILE_SYSTEM_REALM_INTEGRITY_COMMAND;
import static org.wildfly.security.tool.Params.BULK_CONVERT_PARAM;
import static org.wildfly.security.tool.Params.CREDENTIAL_STORE_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.DEFAULT_KEY_PAIR_ALIAS;
import static org.wildfly.security.tool.Params.ENCODED_PARAM;
import static org.wildfly.security.tool.Params.FILE_SEPARATOR;
import static org.wildfly.security.tool.Params.HASH_CHARSET_PARAM;
import static org.wildfly.security.tool.Params.HASH_ENCODING_PARAM;
import static org.wildfly.security.tool.Params.INPUT_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.KEYSTORE_PARAM;
import static org.wildfly.security.tool.Params.KEYSTORE_TYPE_PARAM;
import static org.wildfly.security.tool.Params.KEY_PAIR_ALIAS_PARAM;
import static org.wildfly.security.tool.Params.LEVELS_PARAM;
import static org.wildfly.security.tool.Params.OUTPUT_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.PASSWORD_ENV_PARAM;
import static org.wildfly.security.tool.Params.PASSWORD_PARAM;
import static org.wildfly.security.tool.Params.REALM_NAME_PARAM;
import static org.wildfly.security.tool.Params.SECRET_KEY_ALIAS_PARAM;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.Test;

/** @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a> */
public class FileSystemRealmIntegrityCommandTest extends AbstractCommandTest {

    private static final String RELATIVE_BASE_DIR = "./target/test-classes/filesystem-integrity/";
    private static final String RELATIVE_UNSIGNED_DIR = RELATIVE_BASE_DIR + "fs-unsigned-realms/";
    private static final String RELATIVE_SIGNED_DIR = RELATIVE_BASE_DIR + "fs-signed-realms/";

    /* KeyStores (expires around June 2031) & credential stores used:
     *
     * > fsKeyStore.pfx - PKCS#12 keystore. Two aliases: integrity-key (RSA-4096 key algo, SHA384withRSA signing algo) and
     *                                              integrity-cert (imported certificate of integrity-key)
     * > fsKeyStoreEC.jceks - JCEKS keystore. One alias: curveKeyPair (256-bit EC [secp256r1] key algo, SHA256withECDSA signing algo)
     * > fsKeyStoreEmpty.jks - JKS keystore. No aliases.
     * > fsCredStore.cs - SecretKey credential store. Two SecretKey aliases: secKey and key
     */
    private static final Path FS_KEYSTORE_PATH = Paths.get(RELATIVE_BASE_DIR, "fsKeyStore.pfx");
    private static final Path FS_REALM_SIGNED_PATH = Paths.get(RELATIVE_SIGNED_DIR);
    private static final String KEYSTORE_PASSWORD = "Guk]i%Aua4-wB";

    @Override
    protected String getCommandType() {
        return FILE_SYSTEM_REALM_INTEGRITY_COMMAND;
    }

    @Test
    public void testHelp() {
        String[] args = new String[]{"--help"};
        executeCommandAndCheckStatus(args);
    }

    /** Also tests non-default key pair alias */
    @Test
    public void testSingleUserRealmWithJCEKS() throws IOException {
        String realmName = "fsRealmSingle";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, realmName);
        Path keyStore = Paths.get(RELATIVE_BASE_DIR, "fsKeyStoreEC.jceks");
        String keyStoreType = "JCEKS";
        String keyPairAlias = "curveKeyPair";
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, keyStore.toString(),
                "--" + KEYSTORE_TYPE_PARAM, keyStoreType,
                "--" + KEY_PAIR_ALIAS_PARAM, keyPairAlias,
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD
        };

        runCommand(inputLocation, args, ElytronToolExitStatus_OK);
        assertTrue("Could not find identity `bob` within single user realm: " + FS_REALM_SIGNED_PATH.resolve(realmName),
                FS_REALM_SIGNED_PATH.resolve(Paths.get(realmName, "b", "o")).toFile().exists());

        ScriptParameters params = new ScriptParameters(realmName)
                .setRealmPath(FS_REALM_SIGNED_PATH.resolve(realmName))
                .setKeyStorePath(keyStore)
                .setKeyStorePassword(KEYSTORE_PASSWORD)
                .setKeyPairAlias(keyPairAlias)
                .setKeyStoreType(keyStoreType);
        validateScript(params, FS_REALM_SIGNED_PATH.resolve(realmName + ".cli"));
    }

    @Test
    public void testMultiUserRealmWithSummary() throws IOException {
        String realmName = "fsRealmMultiUser";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, "fsRealm");
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + KEY_PAIR_ALIAS_PARAM, DEFAULT_KEY_PAIR_ALIAS,
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
                "--summary"
        };

        String output = runCommand(inputLocation, args, ElytronToolExitStatus_OK);
        validateMultiUserIdentitiesPresent(realmName);

        // Summary validation
        assertTrue("Could not find header for summary of filesystem-realm-integrity command",
                output.contains("Summary for execution of Elytron Tool command filesystem-realm-integrity"));
        assertTrue("Could not find summary string for CLI configuration",
                output.contains("Options were specified via CLI"));
        assertTrue("Could not find summary string for configuring CLI script",
                output.contains(String.format("Configured script for WildFly named %s.cli at %s.", realmName, FS_REALM_SIGNED_PATH.normalize().toAbsolutePath())));

        ScriptParameters params = new ScriptParameters(realmName)
                .setRealmPath(FS_REALM_SIGNED_PATH)
                .setKeyStorePath(FS_KEYSTORE_PATH)
                .setKeyPairAlias(DEFAULT_KEY_PAIR_ALIAS)
                .setKeyStorePassword(KEYSTORE_PASSWORD);
        validateScript(params, FS_REALM_SIGNED_PATH.resolve(realmName + ".cli"));
    }

    /** Also tests upgrading from {@code urn:elytron:identity.1.1} and non-default secret key alias */
    @Test
    public void testEncryptedRealmWithFourLevels() throws IOException {
        String realmName = "fsRealmEncrypted";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, realmName);
        Path credStorePath = Paths.get(RELATIVE_BASE_DIR, "fsCredStore.cs");
        String secretKey = "secKey";
        String levels = "4";
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
                "--" + CREDENTIAL_STORE_LOCATION_PARAM, credStorePath.toString(),
                "--" + SECRET_KEY_ALIAS_PARAM, secretKey,
                "--" + LEVELS_PARAM, levels
        };

        runCommand(inputLocation, args, ElytronToolExitStatus_OK);
        validateMultiUserIdentitiesPresent(realmName,
                FS_REALM_SIGNED_PATH.resolve(Paths.get(realmName, "M", "F", "W", "G", "MFWGSY3F.xml")),
                FS_REALM_SIGNED_PATH.resolve(Paths.get(realmName, "M", "J", "X", "W", "MJXWE.xml")),
                FS_REALM_SIGNED_PATH.resolve(Paths.get(realmName, "M", "N", "Q", "W", "MNQW2ZLSN5XA.xml")));

        ScriptParameters params = new ScriptParameters(realmName)
                .setRealmPath(FS_REALM_SIGNED_PATH.resolve(realmName))
                .setKeyStorePath(FS_KEYSTORE_PATH)
                .setKeyStorePassword(KEYSTORE_PASSWORD)
                .setCredentialStorePath(credStorePath)
                .setSecretKeyAlias(secretKey)
                .setLevels(levels);
        validateScript(params, FS_REALM_SIGNED_PATH.resolve(realmName + ".cli"));
    }

    @Test
    public void testRealmWithNameEncodedAndPasswordEnv() throws IOException {
        String realmName = "fsRealmNameEncoded";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, realmName);
        String passwordEnvVar = "FS_INTEGRITY_PASSWORD_TEST_VAR";
        String encoded = "false";
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + PASSWORD_ENV_PARAM, passwordEnvVar,
                "--" + ENCODED_PARAM, encoded
        };

        runCommand(inputLocation, args, ElytronToolExitStatus_OK);
        validateMultiUserIdentitiesPresent(realmName);

        ScriptParameters params = new ScriptParameters(realmName)
                .setRealmPath(FS_REALM_SIGNED_PATH.resolve(realmName))
                .setKeyStorePath(FS_KEYSTORE_PATH)
                .setKeyStorePassword(KEYSTORE_PASSWORD);
        validateScript(params, FS_REALM_SIGNED_PATH.resolve(realmName + ".cli"));
    }

    @Test
    public void testRealmWithHashEncoding() throws IOException {
        String realmName = "fsRealmHashEncoding";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, realmName);
        String hashEncoding = "hex";
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + KEY_PAIR_ALIAS_PARAM, DEFAULT_KEY_PAIR_ALIAS,
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
                "--" + HASH_ENCODING_PARAM, hashEncoding
        };

        runCommand(inputLocation, args, ElytronToolExitStatus_OK);
        validateMultiUserIdentitiesPresent(realmName);

        ScriptParameters params = new ScriptParameters(realmName)
                .setRealmPath(FS_REALM_SIGNED_PATH.resolve(realmName))
                .setKeyStorePath(FS_KEYSTORE_PATH)
                .setKeyStorePassword(KEYSTORE_PASSWORD);
        validateScript(params, FS_REALM_SIGNED_PATH.resolve(realmName + ".cli"));
    }

    @Test
    public void testRealmWithHashCharset() throws IOException {
        String realmName = "fsRealmCharset";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, realmName);
        String hashCharset = "ISO-8859-1";
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
                "--" + HASH_CHARSET_PARAM, hashCharset
        };

        runCommand(inputLocation, args, ElytronToolExitStatus_OK);
        validateMultiUserIdentitiesPresent(realmName);

        ScriptParameters params = new ScriptParameters(realmName)
                .setRealmPath(FS_REALM_SIGNED_PATH.resolve(realmName))
                .setKeyStorePath(FS_KEYSTORE_PATH)
                .setKeyStorePassword(KEYSTORE_PASSWORD)
                .setHashCharset(hashCharset);
        validateScript(params, FS_REALM_SIGNED_PATH.resolve(realmName + ".cli"));
    }

    @Test
    public void testRealmUpgradeInPlace() throws IOException {
        String realmName = "fsRealmUpgradeInPlace";
        Path location = Paths.get(RELATIVE_BASE_DIR, realmName);
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, location.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
        };

        String output = runCommand(location, args, ElytronToolExitStatus_OK);
        assertTrue("Expected to find notice about in-place upgrade",
                Pattern.compile("In-place upgrade for descriptor block \\d+: filesystem realm backed up at "
                                + Pattern.quote(location.normalize().toAbsolutePath() + "-backup"))
                        .matcher(output).find());

        ScriptParameters params = new ScriptParameters(realmName)
                .setRealmPath(location)
                .setKeyStorePath(FS_KEYSTORE_PATH)
                .setKeyStorePassword(KEYSTORE_PASSWORD);
        validateScript(params, FS_REALM_SIGNED_PATH.resolve(realmName + ".cli"));
    }

    /**
     * There isn't really a good way of checking for this, without reimplmenting the full verification
     * functionality of {@link org.wildfly.security.auth.realm.FileSystemSecurityRealm FileSystemSecurityRealm}. For
     * now, this test is expected to pass without issue.
     */
    @Test
    public void testIntegrityAlreadyEnabled() throws IOException {
        String realmName = "fsRealmIntegrityEnabled";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, realmName);
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
        };

        runCommand(inputLocation, args, ElytronToolExitStatus_OK);
        validateMultiUserIdentitiesPresent(realmName);

        ScriptParameters params = new ScriptParameters(realmName)
                .setRealmPath(FS_REALM_SIGNED_PATH.resolve(realmName))
                .setKeyStorePath(FS_KEYSTORE_PATH)
                .setKeyStorePassword(KEYSTORE_PASSWORD);
        validateScript(params, FS_REALM_SIGNED_PATH.resolve(realmName + ".cli"));
    }

    @Test
    public void testBulkUpgradeAndRealmEnumeration() {
        // Also run with a summary
        String[] args = {
                "--" + BULK_CONVERT_PARAM, Paths.get("./target/test-classes/bulk-integrity-conversion-desc").toString(),
                "--summary"
        };

        // Empty realm will not be converted
        String output = executeCommandAndCheckStatusAndGetOutput(args, ElytronToolExitStatus_OK);
        assertTrue("Expected to find info about parsing descriptor file",
                output.contains("Options were specified via descriptor file:"));

        // Check for output realms. Unnamed realms will be enumerated as needed
        File[] signedRealmDirs = FS_REALM_SIGNED_PATH.toFile().listFiles();

        assertTrue("Could not find upgraded realm fsRealmUpgradeInPlaceBulk",
                Paths.get(RELATIVE_BASE_DIR, "fsRealmUpgradeInPlaceBulk", "a", "l", "alice-MFWGSY3F.xml").toFile().exists());
        assertTrue("Could not find creation of realm fsRealmEncryptedBulk",
                Paths.get(RELATIVE_SIGNED_DIR, "fsRealmEncryptedBulk", "M","J", "X", "W", "MJXWE.xml" ).toFile().exists());
        assertTrue("No signed filesystem realms could be found in " + FS_REALM_SIGNED_PATH.normalize().toAbsolutePath(),
                signedRealmDirs != null && signedRealmDirs.length > 0);

        /* Path.startsWith() would attempt (and fail) to resolve the prefix as a real path; casting to a String avoids this problem
         * Looking for 2 directories + 2 CLI scripts */
        String enumeratedRealmPrefix = FS_REALM_SIGNED_PATH.normalize().toAbsolutePath()
                + FILE_SEPARATOR + "filesystem-realm-with-integrity-";

        assertEquals("Could not find creation of two enumerated filesystem realms", 4,
                Arrays.stream(signedRealmDirs)
                        .filter(elem -> elem.toPath().normalize().toAbsolutePath().toString().startsWith(enumeratedRealmPrefix))
                        .count());
    }



    @Test
    public void testMissingInputRealm() {
        String realmName = "fsRealmNonExistent";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, realmName);
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
        };

        String output = "";
        try {
            output = executeCommandAndCheckStatusAndGetOutput(args, GENERAL_CONFIGURATION_ERROR);
        } catch (RuntimeException e) {
            output = e.getMessage();
        } finally {
            assertTrue("Expected to find error that input location does not exist",
                    output.contains(ElytronToolMessages.msg.inputLocationDoesNotExist().getMessage()));
        }
    }

    @Test
    public void testEmptyRealm() {
        String realmName = "fsRealmEmpty";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, realmName);
        String[] args = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + KEY_PAIR_ALIAS_PARAM, DEFAULT_KEY_PAIR_ALIAS,
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD
        };

        String output = "";
        try {
            output = executeCommandAndCheckStatusAndGetOutput(args, GENERAL_CONFIGURATION_WARNING);
        } catch (RuntimeException e) {
            output = e.getMessage();
        } finally {
            assertTrue("Expected to find warning message that realm was empty",
                    output.contains("due to no identities present in filesystem realm"));
        }
    }

    @Test
    public void testNotAKeyStore() {
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, "fsRealm");

        String notKSRealmName = "fsRealmNotAKeyStore";
        Path notKeyStore = Paths.get(RELATIVE_BASE_DIR, "fsCredStore.cs");
        String[] notKSArgs = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, notKSRealmName,
                "--" + KEYSTORE_PARAM, notKeyStore.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD
        };

        String output = "";
        try {
            output = executeCommandAndCheckStatusAndGetOutput(notKSArgs, GENERAL_CONFIGURATION_WARNING);
        } catch (RuntimeException e) {
            output = e.getMessage();
        } finally {
            assertTrue("Expected to find warning message that KeyStore format was invalid",
                    output.contains("due to failure to load KeyStore"));
        }
    }

    @Test
    public void testEmptyKeyStore() {
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, "fsRealm");

        String emptyKSRealmName = "fsRealmEmptyKeyStore";
        Path emptyKeyStore = Paths.get(RELATIVE_BASE_DIR, "fsKeyStoreEmpty.jks");
        String[] emptyKSArgs = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, emptyKSRealmName,
                "--" + KEYSTORE_PARAM, emptyKeyStore.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD
        };

        String output = "";
        try {
            output = executeCommandAndCheckStatusAndGetOutput(emptyKSArgs, GENERAL_CONFIGURATION_WARNING);
        } catch (RuntimeException e) {
            output = e.getMessage();
        } finally {
            assertTrue("Expected to find warning message that private or public key was missing",
                    output.contains("due to missing private key"));
        }
    }

    @Test
    public void testNotAKeyPair() {
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, "fsRealm");

        String certRealmName = "fsRealmSecretKey";
        String certAlias = "integrity-cert";
        String[] certArgs = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, certRealmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + KEY_PAIR_ALIAS_PARAM, certAlias,
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD
        };

        String output = "";
        try {
            output = executeCommandAndCheckStatusAndGetOutput(certArgs, GENERAL_CONFIGURATION_WARNING);
        } catch (RuntimeException e) {
            output = e.getMessage();
        } finally {
            assertTrue("Expected to find warning message that private key was missing",
                     output.contains("due to missing private key"));
        }
    }

    @Test
    public void testMissingKeyStore() {
        String realmName = "fsRealmMissingKeyStore";
        Path inputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, "fsRealm");
        Path keyStore = Paths.get(RELATIVE_BASE_DIR, "nonExistentKeyStore.jks");
        String[] emptyKSArgs = {
                "--" + INPUT_LOCATION_PARAM, inputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, realmName,
                "--" + KEYSTORE_PARAM, keyStore.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD
        };

        String output = "";
        try {
            output = executeCommandAndCheckStatusAndGetOutput(emptyKSArgs, GENERAL_CONFIGURATION_ERROR);
        } catch (RuntimeException e) {
            output = e.getMessage();
        } finally {
            assertTrue("Expected to find warning message that key pair was not loaded",
                    output.contains(ElytronToolMessages.msg.keyStoreDoesNotExist().getMessage()));
        }
    }

    @Test
    public void testInvalidIdentityVersion() {
        // Schema version is invalid
        String invalidRealmName = "fsRealmInvalidIdentityVersion";
        Path invalidInputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, invalidRealmName);
        String[] invalidArgs = {
                "--" + INPUT_LOCATION_PARAM, invalidInputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, invalidRealmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
        };

        try {
            executeCommandAndCheckStatusAndGetOutput(invalidArgs, GENERAL_CONFIGURATION_ERROR);
        } catch (RuntimeException ignored) {}
    }

    @Test
    public void testMissingIdentityVersion() {
        // Schema version attribute is missing
        String missingRealmName = "fsRealmMissingIdentityVersion";
        Path missingInputLocation = Paths.get(RELATIVE_UNSIGNED_DIR, missingRealmName);
        String[] missingArgs = {
                "--" + INPUT_LOCATION_PARAM, missingInputLocation.toString(),
                "--" + OUTPUT_LOCATION_PARAM, FS_REALM_SIGNED_PATH.toString(),
                "--" + REALM_NAME_PARAM, missingRealmName,
                "--" + KEYSTORE_PARAM, FS_KEYSTORE_PATH.toString(),
                "--" + PASSWORD_PARAM, KEYSTORE_PASSWORD,
        };
        try {
            executeCommandAndCheckStatusAndGetOutput(missingArgs, GENERAL_CONFIGURATION_ERROR);
        } catch (RuntimeException ignored) {}
    }

    @Test
    public void testInvalidBulkUpgrade() {
        String[] args = {
                "--" + BULK_CONVERT_PARAM, Paths.get("./target/test-classes/bulk-integrity-conversion-desc-INVALID").toString(),
                "--summary"
        };

        String output = executeCommandAndCheckStatusAndGetOutput(args, GENERAL_CONFIGURATION_WARNING);
        assertTrue("Expected to find info about parsing descriptor file",
                output.contains("Options were specified via descriptor file:"));

        assertTrue("Could not find warning for missing required input-location",
                output.contains("due to missing input realm location."));
        assertTrue("Could not find warning for skipping block due to \"missing required parameter\"",
                output.contains("due to missing required parameter."));
        assertTrue("Could not find warning for missing required password",
                output.contains("due to missing KeyStore password."));
    }

    private String runCommand(Path inputLocation, String[] args, int expectedStatus) {
        String output = executeCommandAndCheckStatusAndGetOutput(args, expectedStatus);
        assertTrue("Could not find creation of realm " + inputLocation,
                output.contains(ElytronToolMessages.msg.fileSystemRealmIntegrityCreatingRealm(inputLocation.normalize().toAbsolutePath().toString())));

        return output;
    }

    /** Uses default relative paths for identities, as present in {@code resources/fs-unsigned-realms/fsRealm/} */
    private void validateMultiUserIdentitiesPresent(String realmName) {
        validateMultiUserIdentitiesPresent(realmName,
                FS_REALM_SIGNED_PATH.resolve(Paths.get(realmName, "a", "l", "alice-MFWGSY3F.xml")),
                FS_REALM_SIGNED_PATH.resolve(Paths.get(realmName, "b", "o", "bob-MJXWE.xml")),
                FS_REALM_SIGNED_PATH.resolve(Paths.get(realmName, "c", "a", "cameron-MNQW2ZLSN5XA.xml")));
    }

    /**
     * Assert that all converted identity files are present.
     *
     * @param realmName name of the output filesystem realm
     * @param alicePath full path to the identity "alice"
     * @param bobPath full path to the identity "bob"
     * @param cameronPath full path to the identity "cameron"
     * */
    private void validateMultiUserIdentitiesPresent(String realmName, Path alicePath, Path bobPath, Path cameronPath) {
        assertTrue("Could not find identity `alice` within multi-user realm: " + FS_REALM_SIGNED_PATH.resolve(realmName),
                alicePath.toFile().exists());
        assertTrue("Could not find identity `bob` within multi-user realm: " + FS_REALM_SIGNED_PATH.resolve(realmName),
                bobPath.toFile().exists());
        assertTrue("Could not find identity `cameron` within multi-user realm: " + FS_REALM_SIGNED_PATH.resolve(realmName),
                cameronPath.toFile().exists());
    }

    /**
     * Validate that all expected parameters are present in the CLI script file.
     *
     * @param params parameters to check within the CLI script
     * @param scriptPath full path to the CLI script file.
     * @throws IOException if an exception occurs while reading the script
     */
    private void validateScript(ScriptParameters params, Path scriptPath) throws IOException {
        if (scriptPath.toFile().exists()) {
            List<String> script = Files.readAllLines(scriptPath);

            // Identify line adding filesystem realm
            String realmLine = null;
            String realmName = params.getRealmName();
            for (String line : script) {
                if (line.contains(realmName)) {
                    realmLine = line;
                }
            }
            assertNotNull(String.format("Filesystem realm %s was not present in the CLI script", realmName),
                    realmLine);

            // Identify lines adding keystore (mykeystore#) and optional credential store (mycredstore#)
            Matcher keyStoreNameMatcher = Pattern.compile("^.*key-store=(mykeystore\\d+).*$").matcher(realmLine);
            assertTrue(keyStoreNameMatcher.matches());

            String keyStoreLine = null;
            String keyStoreName = keyStoreNameMatcher.group(1);
            String credStoreLine = null;
            String credStoreName = null;

            Matcher credStoreNameMatcher = Pattern.compile("^.*credential-store=(mycredstore\\d+).*$").matcher(realmLine);
            if (credStoreNameMatcher.matches()) {
                credStoreName = credStoreNameMatcher.group(1);
            }

            for (String line : script) {
                if (line.startsWith("/subsystem=elytron/key-store=")) {
                    keyStoreLine = line;
                } else if (line.startsWith("/subsystem=elytron/secret-key-credential-store=")) {
                    credStoreLine = line;
                }
            }

            assertNotNull(String.format("KeyStore %s for filesystem realm %s was not present in the CLI script", keyStoreName, realmName),
                    keyStoreLine);

            if (credStoreLine != null) {
                assertTrue(String.format("Configuration for credential store was found in CLI script for realm %s, but was not specified in parameters", realmName),
                        params.credentialStoreProvided());
            } else {
                assertFalse(String.format("Credential store %s for filesystem realm %s was not present in the CLI script", credStoreName, realmName),
                        params.credentialStoreProvided());
            }

            for (ImmutablePair<ScriptParameters.RESOURCES, String> param : params.getScriptParameters()) {
                switch (param.getKey()) {
                    case FILESYSTEM_REALM:
                        assertTrue(String.format("Parameter %s could not be found in configuration for filesystem realm %s.\n"
                                                + "Command found: %s", param.getValue(), realmName, realmLine),
                                realmLine.contains(param.getValue())
                        );
                        break;
                    case KEY_STORE:
                        assertTrue(String.format("Parameter %s could not be found in configuration for keystore %s.\n"
                                                + "Command found: %s", param.getValue(), keyStoreName, keyStoreLine),
                                keyStoreLine.contains(param.getValue())
                        );
                        break;
                    case CREDENTIAL_STORE:
                        assertTrue(String.format("Parameter %s could not be found in configuration for credential store %s.\n"
                                        + "Command found: %s", param.getValue(), credStoreName, credStoreLine),
                                credStoreLine.contains(param.getValue())
                        );
                        break;
                    default:
                        throw new IllegalArgumentException(String.format("Unknown resource %s provided for parameter %s",
                                param.getKey(), param.getValue()));
                }
            }
        }
    }

    /** Set the parameters to check for in the CLI script. */
    static class ScriptParameters {
        // Ordered based on position in script file
        public enum RESOURCES {KEY_STORE, CREDENTIAL_STORE, FILESYSTEM_REALM}

        private final String realmName;
        private String realmPath;
        private String keyPairAlias;
        private String secretKeyAlias;
        private String levels;
        private String hashCharset;

        private String keyStorePath;
        private String keyStorePassword;
        private String keyStoreType;
        private String credentialStorePath;

        public ScriptParameters(String realmName) {
            this.realmName = realmName;
            this.realmPath = null;
            this.keyPairAlias = null;
            this.secretKeyAlias = null;
            this.levels = null;
            this.hashCharset = null;
            this.keyStorePath = null;
            this.keyStorePassword = null;
            this.keyStoreType = null;
            this.credentialStorePath = null;
        }

        ScriptParameters(ScriptParameters parameters) {
            this.realmName = parameters.realmName;
            this.realmPath = parameters.realmPath;
            this.keyPairAlias = parameters.keyPairAlias;
            this.secretKeyAlias = parameters.secretKeyAlias;
            this.levels = parameters.levels;
            this.hashCharset = parameters.hashCharset;
            this.keyStorePath = parameters.keyStorePath;
            this.keyStorePassword = parameters.keyStorePassword;
            this.keyStoreType = parameters.keyStoreType;
            this.credentialStorePath = parameters.credentialStorePath;
        }

        /** @return An {@link ArrayList} matching Elytron resources to formatted CLI script parameters.   */
        public ArrayList<ImmutablePair<RESOURCES, String>> getScriptParameters() {
            ArrayList<ImmutablePair<RESOURCES, String>> scriptParams = new ArrayList<>();

            if (realmName != null) scriptParams.add(new ImmutablePair<>(RESOURCES.FILESYSTEM_REALM, "filesystem-realm="+realmName));
            if (realmPath != null) scriptParams.add(new ImmutablePair<>(RESOURCES.FILESYSTEM_REALM, "path="+realmPath));
            if (keyPairAlias != null) scriptParams.add(new ImmutablePair<>(RESOURCES.FILESYSTEM_REALM, "key-store-alias="+keyPairAlias));
            if (secretKeyAlias != null) scriptParams.add(new ImmutablePair<>(RESOURCES.FILESYSTEM_REALM, "secret-key="+secretKeyAlias));
            if (levels != null) scriptParams.add(new ImmutablePair<>(RESOURCES.FILESYSTEM_REALM, "levels="+levels));
            if (hashCharset != null) scriptParams.add(new ImmutablePair<>(RESOURCES.FILESYSTEM_REALM, "hash-charset="+hashCharset));
            if (keyStorePath != null) scriptParams.add(new ImmutablePair<>(RESOURCES.KEY_STORE, "path="+keyStorePath));
            if (keyStorePassword != null) scriptParams.add(new ImmutablePair<>(RESOURCES.KEY_STORE, "credential-reference={clear-text=\""+keyStorePassword+"\"}"));
            if (keyStoreType != null) scriptParams.add(new ImmutablePair<>(RESOURCES.KEY_STORE, "type="+keyStoreType));
            if (credentialStorePath != null) scriptParams.add(new ImmutablePair<>(RESOURCES.CREDENTIAL_STORE, "path="+credentialStorePath));

            return scriptParams;
        }

        public String getRealmName() {
            return this.realmName;
        }

        public boolean credentialStoreProvided() {
            return this.credentialStorePath != null;
        }

        public ScriptParameters setRealmPath(Path realmPath) {
            this.realmPath = realmPath.normalize().toAbsolutePath().toString();
            return new ScriptParameters(this);
        }
        public ScriptParameters setKeyStorePassword(String keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
            return new ScriptParameters(this);
        }
        public ScriptParameters setSecretKeyAlias(String secretKeyAlias) {
            this.secretKeyAlias = secretKeyAlias;
            return new ScriptParameters(this);
        }
        public ScriptParameters setLevels(String levels) {
            this.levels = levels;
            return new ScriptParameters(this);
        }
        public ScriptParameters setHashCharset(String hashCharset) {
            this.hashCharset = hashCharset;
            return new ScriptParameters(this);
        }
        public ScriptParameters setKeyStorePath(Path keyStorePath) {
            this.keyStorePath = keyStorePath.normalize().toAbsolutePath().toString();
            return new ScriptParameters(this);
        }
        public ScriptParameters setKeyStoreType(String keyStoreType) {
            this.keyStoreType = keyStoreType;
            return new ScriptParameters(this);
        }
        public ScriptParameters setKeyPairAlias(String keyPairAlias) {
            this.keyPairAlias = keyPairAlias;
            return new ScriptParameters(this);
        }
        public ScriptParameters setCredentialStorePath(Path credentialStorePath) {
            this.credentialStorePath = credentialStorePath.normalize().toAbsolutePath().toString();
            return new ScriptParameters(this);
        }
    }
}
