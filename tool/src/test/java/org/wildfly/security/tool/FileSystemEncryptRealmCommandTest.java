/*
 * JBoss, Home of Professional Open Source
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.tool.FileSystemEncryptRealmCommand.ELYTRON_PASSWORD_PROVIDERS;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import org.apache.commons.cli.MissingArgumentException;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.PropertiesCredentialStore;
import org.wildfly.security.evidence.PasswordGuessEvidence;

public class FileSystemEncryptRealmCommandTest extends AbstractCommandTest{

    private static final String RELATIVE_BASE_DIR = "./target/test-classes/filesystem-encrypt/";

    private void run(String inputLocation, String outputLocation, String fileSystemRealmName, int expectedStatus) {
        runCommandSilent(inputLocation, outputLocation, fileSystemRealmName, expectedStatus);
    }

    private void run(String bulkConvertFile, int expectedStatus) {
        runCommandSilent(bulkConvertFile, expectedStatus);
    }

    private void runCommand(String inputLocation, String outputLocation, String fileSystemRealmName, String encoded, boolean create, int expectedStatus) {
        String[] requiredArgs;
        requiredArgs = new String[]{"--input-location", inputLocation, "--output-location", outputLocation, "--realm-name", fileSystemRealmName, "--encoded", encoded, "--create", String.valueOf(create), "--credential-store", "mycredstore.cs"};
        executeCommandAndCheckStatus(requiredArgs, expectedStatus);
    }

    private void runCommand(String inputLocation, String outputLocation, String fileSystemRealmName, int levels, String encoded, boolean create, int expectedStatus) {
        String[] requiredArgs;
        requiredArgs = new String[]{"--input-location", inputLocation, "--output-location", outputLocation, "--realm-name", fileSystemRealmName, "--levels", String.valueOf(levels), "--encoded", encoded, "--create", String.valueOf(create), "--credential-store", "mycredstore.cs"};
        executeCommandAndCheckStatus(requiredArgs, expectedStatus);
    }

    private void runCommand(String inputLocation, String outputLocation, String fileSystemRealmName, String credentialStore, String secretKey, String encoded, boolean create, int expectedStatus) {
        String[] requiredArgs;
        requiredArgs = new String[]{"--input-location", inputLocation, "--output-location", outputLocation, "--realm-name", fileSystemRealmName, "--credential-store", credentialStore, "--secret-key", secretKey, "--encoded", encoded, "--create", String.valueOf(create), "--credential-store", "mycredstore.cs"};
        executeCommandAndCheckStatus(requiredArgs, expectedStatus);
    }

    private void runCommand(String bulkConvertFile, int expectedStatus) {
        String[] requiredArgs;
        requiredArgs = new String[]{"--bulk-convert", bulkConvertFile};
        executeCommandAndCheckStatus(requiredArgs, expectedStatus);
    }

    private void runCommandInvalid(String outputLocation, String fileSystemRealmName, String encoded, boolean create, int expectedStatus) {
        String[] requiredArgs;
        requiredArgs = new String[]{"--output-location", outputLocation, "--realm-name", fileSystemRealmName, "--encoded", encoded, "--create", String.valueOf(create), "--credential-store", "mycredstore.cs"};
        executeCommandAndCheckStatus(requiredArgs, expectedStatus);
    }

    private void runCommandSilent(String inputLocation, String outputLocation, String fileSystemRealmName, int expectedStatus) {
        String[] requiredArgsSilent;
        requiredArgsSilent = new String[]{"--input-location", inputLocation, "--output-location", outputLocation, "--realm-name", fileSystemRealmName, "--silent"};
        executeCommandAndCheckStatus(requiredArgsSilent, expectedStatus);
    }

    private void runCommandSilent(String bulkConvertFile, int expectedStatus) {
        String[] requiredArgsSilent;
        requiredArgsSilent = new String[]{"--bulk-convert", bulkConvertFile, "--silent"};
        executeCommandAndCheckStatus(requiredArgsSilent, expectedStatus);
    }

    @Override
    protected String getCommandType() {
        return FileSystemEncryptRealmCommand.FILE_SYSTEM_ENCRYPT_COMMAND;
    }

    @Test
    public void testHelp() {
        String[] args = new String[]{"--help"};
        executeCommandAndCheckStatus(args);
    }

    @Test
    public void testBulk() throws Exception {
        String descriptorFileLocation = "./target/test-classes/bulk-encryption-conversion-desc";
        runCommand(descriptorFileLocation, 0);
        String[] files = new String[]{"multiple-credential-types/O/OBWGC2LOKVZWK4Q.xml", "multiple-credential-types/O/ONQWY5DFMRKXGZLS.xml", "multiple-credential-types/O/OVZWK4RUGI.xml", "multiple-credential-types/M/MFXG65DIMVZFK43FOI.xml", "multiple-credential-types/M/MFZWQ4DBNY.xml", "multiple-credential-types/N/NZSXOU3BNR2GKZCVONSXEMQ.xml", "hash-encoding/O/B/OBSXE43PNYZA.xml", "hash-encoding/O/5/O5UWYZDGNR4TO.xml", "hash-encoding/O/V/OVZWK4RR.xml", "hash-encoding/M/J/MJXXSNA.xml", "hash-encoding/M/5/M5UXE3BV.xml", "hash-encoding/M/V/MVQXAOA.xml", "hash-encoding/N/J/NJRG643TGY.xml", "hash-encoding/N/F/NFSGK3TUNF2HSMY.xml", "hash-charset/O/B/OBSXE43PNYZA.xml", "hash-charset/O/5/O5UWYZDGNR4TO.xml", "hash-charset/O/V/OVZWK4RR.xml", "hash-charset/M/J/MJXXSNA.xml", "hash-charset/M/5/M5UXE3BV.xml", "hash-charset/M/V/MVQXAOA.xml", "hash-charset/N/J/NJRG643TGY.xml", "hash-charset/N/F/NFSGK3TUNF2HSMY.xml", "level-4/O/B/S/X/OBSXE43PNYZA.xml", "level-4/O/5/U/W/O5UWYZDGNR4TO.xml", "level-4/O/V/Z/W/OVZWK4RR.xml", "level-4/M/J/X/X/MJXXSNA.xml", "level-4/M/5/U/X/M5UXE3BV.xml", "level-4/M/V/Q/X/MVQXAOA.xml", "level-4/N/J/R/G/NJRG643TGY.xml", "level-4/N/F/S/G/NFSGK3TUNF2HSMY.xml"};
        for (String file: files) {
            if(!fileExists("target/test-classes/filesystem-encrypt/fs-encrypted-realms/"+file)){
                throw new FileNotFoundException("Missing file from Bulk Descriptor File: " + file);
            }
        }
    }

    @Test
    public void testBulkMissingParam() throws Exception {
        String descriptorFileLocation = "./target/test-classes/bulk-encryption-conversion-desc-INVALID";
        runCommand(descriptorFileLocation, 1);
    }

    @Test
    public void testSingleUser() throws Exception {
        String inputLocation = RELATIVE_BASE_DIR + "fs-unencrypted-realms/single-user/";
        String outputLocation = RELATIVE_BASE_DIR + "fs-encrypted-realms";
        String fileSystemRealmName = "single-user";
        runCommand(inputLocation, outputLocation, fileSystemRealmName, "false", true, 0);
        String file = "target/test-classes/filesystem-encrypt/fs-encrypted-realms/single-user/N/B/NBSWY3DP.xml";
        if(!fileExists(file)){
            throw new FileNotFoundException("Encrypted Identity/Identities Missing: " + file);
        }
    }

    @Test
    public void testSingleUserMissingParam() throws Exception {
        String outputLocation = RELATIVE_BASE_DIR + "fs-encrypted-realms";
        String fileSystemRealmName = "single-user";
        Exception exception = assertThrows(RuntimeException.class, () -> {
            runCommandInvalid(outputLocation, fileSystemRealmName, "false", true, 1);
        });
        assertTrue(exception.getCause() instanceof MissingArgumentException);
    }

    @Test
    public void testSingleUserWithRoles() throws Exception {
        String inputLocation = RELATIVE_BASE_DIR + "fs-unencrypted-realms/single-user-with-role/";
        String outputLocation = RELATIVE_BASE_DIR + "fs-encrypted-realms";
        String fileSystemRealmName = "single-user-with-role";
        runCommand(inputLocation, outputLocation, fileSystemRealmName, 3, "false", true, 0);
        String file = "target/test-classes/filesystem-encrypt/fs-encrypted-realms/single-user-with-role/O/B/S/OBSXE43PNYYTEMY.xml";
        if(!fileExists(file)){
            throw new FileNotFoundException("Encrypted Identity/Identities Missing: " + file);
        }
    }

    @Test
    public void testSingleUserWithRolesAndKey() throws Exception {
        String inputLocation = RELATIVE_BASE_DIR + "fs-unencrypted-realms/single-user-with-key/";
        String outputLocation = RELATIVE_BASE_DIR + "fs-encrypted-realms";
        String fileSystemRealmName = "single-user-with-key";
        String credentialStore = RELATIVE_BASE_DIR + "mycredstore.cs";
        String key = "key";
        runCommand(inputLocation, outputLocation, fileSystemRealmName, credentialStore, key, "false", false, 0);
        String file = "target/test-classes/filesystem-encrypt/fs-encrypted-realms/single-user-with-key/O/N/ONSWG4TFORYGK4TTN5XA.xml";
        if(!fileExists(file)){
            throw new FileNotFoundException("Encrypted Identity/Identities Missing: " + file);
        }
    }

    @Test
    public void testSingleUserAndVerify() throws Exception {
        String inputLocation = RELATIVE_BASE_DIR + "fs-unencrypted-realms/single-user/";
        String outputLocation = RELATIVE_BASE_DIR + "fs-encrypted-realms";
        String fileSystemRealmName = "verify";
        String credentialStoreLocation = RELATIVE_BASE_DIR + "mycredstore.cs";
        String keyAlias = "key";
        runCommand(inputLocation, outputLocation, fileSystemRealmName, credentialStoreLocation, keyAlias, "false", false, 0);

        Map<String, String> implProps = new HashMap<>();
        implProps.put("create", Boolean.FALSE.toString());
        implProps.put("location", credentialStoreLocation);
        implProps.put("modifiable", Boolean.TRUE.toString());
        CredentialStore credentialStore = CredentialStore.getInstance(PropertiesCredentialStore.NAME);
        credentialStore.initialize(implProps);
        SecretKey key = credentialStore.retrieve("key", SecretKeyCredential.class).getSecretKey();
        FileSystemSecurityRealm securityRealm = FileSystemSecurityRealm.builder()
                .setRoot(Paths.get(outputLocation, fileSystemRealmName))
                .setLevels(2)
                .setProviders(ELYTRON_PASSWORD_PROVIDERS)
                .setSecretKey(key)
            .build();
        ModifiableRealmIdentity existingIdentity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("hello"));
        assertTrue(existingIdentity.exists());
        assertTrue(existingIdentity.verifyEvidence(new PasswordGuessEvidence("password!4".toCharArray())));
        existingIdentity.dispose();
    }

    private boolean fileExists(String path) {
        File tempFile = new File(path);
        return tempFile.exists();
    }
}
