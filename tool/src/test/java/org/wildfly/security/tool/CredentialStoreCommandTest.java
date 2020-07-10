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

import java.io.IOException;
import java.io.InputStream;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

import org.apache.commons.cli.AlreadySelectedException;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;

import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import org.junit.Assume;

/**
 * Test for "credential-store" command.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 * @author Hynek Švábek <hsvabek@redhat.com>
 */
public class CredentialStoreCommandTest extends AbstractCommandTest {

    public static final String RSA_ALGORITHM = "RSA";
    public static final String DSA_ALGORITHM = "DSA";
    public static final String EC_ALGORITHM = "EC";

    @Override
    protected String getCommandType() {
        return CredentialStoreCommand.CREDENTIAL_STORE_COMMAND;
    }

    /**
     * basic test with --password option.
     */
    @Test
    public void clearTextCSPassword() {
        String storeFileName = getStoragePathForNewFile();

        String[] args = {"--location=" + storeFileName, "--create",
                "--add", "testalias", "--secret", "secret2", "--summary", "--password", "cspassword"};
        executeCommandAndCheckStatus(args);
    }

    /**
     * basic test with --password and masking password options.
     * @throws Exception if something goes wrong
     */
    @Test
    public void maskCSPassword() {
        String storeFileName = getStoragePathForNewFile();

        String[] args = {"--location=" + storeFileName, "--create",
                "--add", "testalias", "--secret", "secret2", "--summary", "--password", "cspassword", "--salt", "A1B2C3D4", "--iteration", "100"};

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.contains("MASK-"));
    }

    /**
     * basic test without --password option.
     * @throws Exception if something goes wrong
     */
    @Ignore("Issue #15 - bypass prompting using callback handler")
    @Test(expected = CredentialStoreException.class)
    public void noPasswordSpecified() throws Exception {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String storeFileName = getStoragePathForNewFile();

        String[] args = {"--location=" + storeFileName, "--create",
                "--add", "testalias", "--secret", "secret2", "--summary", "--salt", "A1B2C3D4", "--iteration", "100"};

        command.execute(args);
    }

    @Test
    public void testAddAlias() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);
    }

    private void changeExecutable(Path path) throws IOException {
        boolean canExecute = Files.isExecutable(path);
        if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            if (canExecute) {
                perms.remove(PosixFilePermission.OWNER_EXECUTE);
            } else {
                perms.add(PosixFilePermission.OWNER_EXECUTE);
            }
            Files.setPosixFilePermissions(path, perms);
        } else {
            AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
            AclEntry entry = AclEntry.newBuilder()
                    .setType(canExecute? AclEntryType.DENY : AclEntryType.ALLOW)
                    .setPrincipal(view.getOwner())
                    .setPermissions(AclEntryPermission.EXECUTE)
                    .build();
            List<AclEntry> acl = view.getAcl();
            acl.add(0, entry);
            view.setAcl(acl);
        }
    }

    @Test
    public void testKeepFilePermissions() throws Exception {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret";
        String aliasName2 = "testalias2";
        String aliasValue2 = "secret2";
        Path storagePath = Paths.get(storageLocation);
        Assume.assumeTrue(storagePath.getFileSystem().supportedFileAttributeViews().contains("posix") ||
                storagePath.getFileSystem().supportedFileAttributeViews().contains("acl"));

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);

        // change execute permission of the file to make it different to a new created one
        assertTrue("Credetial store location is created", Files.exists(storagePath));
        Map<String, Object> originalPermissions = CredentialStoreCommand.readAttributesForPreservation(storagePath);
        changeExecutable(storagePath);
        Map<String, Object> locationPermissionsBeforeFlush = CredentialStoreCommand.readAttributesForPreservation(storagePath);
        Assert.assertNotEquals("Attributes are different to the original file", originalPermissions, locationPermissionsBeforeFlush);

        // add a second alias to change the file
        String[] args2 = { "--location=" + storageLocation, "--create", "--add", aliasName2, "--secret",
                aliasValue2, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args2);
        store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName2, aliasValue2);

        // check attributes are maintained and the executable perm remains modified
        Map<String, Object> locationPermissionsAfterFlush = CredentialStoreCommand.readAttributesForPreservation(storagePath);
        assertEquals("Attributes to preserve are the same", locationPermissionsBeforeFlush, locationPermissionsAfterFlush);
    }

    @Test
    public void testAddAliasCustomWithoutFlush() throws Exception {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret";

        String[] argsCreate = {
            "--create",
            "--credential-store-provider=" + CustomPropertiesProvider.CUSTOM_PROPERTIES_PROVIDER,
            "--type=" + CustomPropertiesCredentialStore.CUSTOM_PROPERTIES_CREDENTIAL_STORE,
            "--location=" + storageLocation,
            "--add", aliasName,
            "--secret", aliasValue,
            "--summary",
            "--password", storagePassword};
        executeCommandAndCheckStatus(argsCreate);

       // check the alias is there
       String[] argsAliases = {
            "--aliases", "--summary",
            "--credential-store-provider=" + CustomPropertiesProvider.CUSTOM_PROPERTIES_PROVIDER,
            "--type=" + CustomPropertiesCredentialStore.CUSTOM_PROPERTIES_CREDENTIAL_STORE,
            "--location=" + storageLocation,
            "--password", storagePassword};
        String output = executeCommandAndCheckStatusAndGetOutput(argsAliases);
        assertTrue(output.startsWith("Credential store contains following aliases: " + aliasName));

        // load the properties file directly and check the password is OK
        assertTrue("Properties file is created", Files.exists(Paths.get(storageLocation)));
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(Paths.get(storageLocation))) {
            props.load(in);
        }
        assertEquals("The properties file contains 1 entry", 1, props.size());
        assertEquals("The properties file contains the secret", aliasValue, props.getProperty(aliasName));
    }

    @Test
    public void testAliasesList() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String[] aliasNames = { "testalias1", "testalias2", "testalias3" };
        String[] aliasValues = {"secret1", "secret2", "secret3"};

        for (int i = 0; i < aliasNames.length; i++) {
            try {
                createStoreAndAddAliasAndCheck(storageLocation, storagePassword, aliasNames[i], aliasValues[i]);
            } catch (RuntimeException e) {
                if (!(e.getCause() instanceof NullPointerException)) {
                    Assert.fail("It must fail because of there is forbidden to use empty alias name or value.");
                }
            }
        }

        String[] args = new String[] { "--location=" + storageLocation, "--create", "--aliases", "--summary",
                "--password", storagePassword, "--properties", "keyStoreType=JCEKS;keyAlias=not_relevant"};
        executeCommandAndCheckStatus(args);

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.startsWith("Credential store contains following aliases:"));
        for (String aliasName : aliasNames) {
            if (!output.contains(aliasName)) {
                Assert.fail(String.format("Credential store must contain aliasName [%s]. But output is [%s].",
                    aliasName, output));
            }
        }
    }

    @Test
    public void testGenerateKeyPairDefault() throws CredentialStoreException {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";

        String[] args = { "--location=" + storageLocation, "--create", "--generate-key-pair", aliasName, "--summary",
                "--password", storagePassword };
        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        KeyPairCredential credential = store.retrieve(aliasName, KeyPairCredential.class);
        KeyPair keyPair = credential.getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(RSA_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(RSA_ALGORITHM, keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testGenerateKeyPairRSA() throws CredentialStoreException {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String algorithm = RSA_ALGORITHM;
        String size = "3072";

        String[] args = { "--location=" + storageLocation, "--create", "--generate-key-pair", aliasName, "--algorithm",
                algorithm, "--size", size, "--summary", "--password", storagePassword};
        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        KeyPairCredential credential = store.retrieve(aliasName, KeyPairCredential.class);
        KeyPair keyPair = credential.getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(RSA_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(RSA_ALGORITHM, keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testGenerateKeyPairDSA() throws CredentialStoreException {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String algorithm = DSA_ALGORITHM;
        String size = "2048";

        String[] args = { "--location=" + storageLocation, "--create", "--generate-key-pair", aliasName, "--algorithm",
                algorithm, "--size", size, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        KeyPair keyPair = store.retrieve(aliasName, KeyPairCredential.class).getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(DSA_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(DSA_ALGORITHM, keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testGenerateKeyPairECDSA() throws CredentialStoreException {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String algorithm = EC_ALGORITHM;
        String size = "521";

        String[] args = { "--location=" + storageLocation, "--create", "--generate-key-pair", aliasName, "--algorithm",
                algorithm, "--size", size, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        KeyPair keyPair = store.retrieve(aliasName, KeyPairCredential.class).getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testExportPublicKey() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";

        String[] createArgs = { "--location=" + storageLocation, "--create", "--generate-key-pair", aliasName, "--summary",
                "--password", storagePassword };
        executeCommandAndCheckStatus(createArgs);

        String[] exportArgs  = { "--location=" + storageLocation, "--export-key-pair-public-key", aliasName, "--summary",
                "--password", storagePassword };
        String output = executeCommandAndCheckStatusAndGetOutput(exportArgs);
        Assert.assertTrue(output.contains("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"));
    }

    @Test
    public void testImportOpenSSHKeyPairFromFile() throws CredentialStoreException {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String passphrase = "secret";
        String keyLocation = "src/test/resources/ssh-keys/id_ecdsa";

        String[] importArgs = { "--location=" + storageLocation, "--create", "--import-key-pair", aliasName, "--key-passphrase",
                passphrase, "--private-key-location", keyLocation, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(importArgs);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        KeyPairCredential credential = store.retrieve(aliasName, KeyPairCredential.class);
        KeyPair keyPair = credential.getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testImportPKCSKeyPairFromFile() throws CredentialStoreException {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String passphrase = "secret";
        String privatekeyLocation = "src/test/resources/ssh-keys/id_ecdsa_pkcs";
        String publickeyLocation = "src/test/resources/ssh-keys/id_ecdsa_pkcs.pub";

        String[] importArgs = { "--location=" + storageLocation, "--create", "--import-key-pair", aliasName, "--key-passphrase",
                passphrase, "--private-key-location", privatekeyLocation, "--public-key-location", publickeyLocation,
                "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(importArgs);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        KeyPairCredential credential = store.retrieve(aliasName, KeyPairCredential.class);
        KeyPair keyPair = credential.getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testImportOpenSSHKeyPairFromString() throws CredentialStoreException {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String passphrase = "secret";
        String key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCdRswttV\n" +
                "UNQ6nKb6ojozTGAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\n" +
                "dHAyNTYAAABBBAKxnsRT7n6qJLKoD3mFfAvcH5ZFUyTzJVW8t60pNgNaXO4q5S4qL9yCCZ\n" +
                "cKyg6QtVgRuVxkUSseuR3fiubyTnkAAADQq3vrkvuSfm4n345STr/i/29FZEFUd0qD++B2\n" +
                "ZoWGPKU/xzvxH7S2GxREb5oXcIYO889jY6mdZT8LZm6ZZig3rqoEAqdPyllHmEadb7hY+y\n" +
                "jwcQ4Wr1ekGgVwNHCNu2in3cYXxbrYGMHc33WmdNrbGRDUzK+EEUM2cwUiM7Pkrw5s88Ff\n" +
                "IWI0V+567Ob9LxxIUO/QvSbKMJGbMM4jZ1V9V2Ti/GziGJ107CBudZr/7wNwxIK86BBAEg\n" +
                "hfnrhYBIaOLrtP8R+96i8iu4iZAvcIbQ==\n" +
                "-----END OPENSSH PRIVATE KEY-----";

        String[] importArgs = { "--location=" + storageLocation, "--create", "--import-key-pair", aliasName, "--key-passphrase",
                passphrase, "--private-key-string", key, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(importArgs);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        KeyPair keyPair = store.retrieve(aliasName, KeyPairCredential.class).getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testImportPKCSKeyPairFromString() throws CredentialStoreException {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String passphrase = "secret";
        String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgj+ToYNaHz/pISg/Z\n" +
                "I9BjdhcTre/SJpIxASY19XtOV1ehRANCAASngcxUTBf2atGC5lQWCupsQGRNwwnK\n" +
                "6Ww9Xt37SmaHv0bX5n1KnsAal0ykJVKZsD0Z09jVF95jL6udwaKpWQwb\n" +
                "-----END PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp4HMVEwX9mrRguZUFgrqbEBkTcMJ\n" +
                "yulsPV7d+0pmh79G1+Z9Sp7AGpdMpCVSmbA9GdPY1RfeYy+rncGiqVkMGw==\n" +
                "-----END PUBLIC KEY-----\n";

        String[] importArgs = { "--location=" + storageLocation, "--create", "--import-key-pair", aliasName, "--key-passphrase",
                passphrase, "--private-key-string", privateKey, "--public-key-string", publicKey, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(importArgs);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        KeyPair keyPair = store.retrieve(aliasName, KeyPairCredential.class).getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void testRemoveAlias() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);

        args = new String[] { "--location=" + storageLocation, "--create", "--remove", aliasName,
                "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkNonExistsAlias(store, aliasName);
    }

    @Test
    public void testUpdateAlias() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";
        String aliasNewSecretValue = "updatedSecretValue";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);

        args = new String[] { "--location=" + storageLocation, "--create", "--add", aliasName,
                "--secret", aliasNewSecretValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasNewSecretValue);
    }

    @Test
    public void testExistsAlias() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);

        args = new String[] { "--location=" + storageLocation, "--create", "--exists", aliasName,
                "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkExistsAlias(store, aliasName);
    }

    @Test
    public void testMaskedPassword() {
        String clearTextPassword = "secret_password";
        String expectedMaskedPassword = "MASK-1GhfMaq4jSY0.kFFU3QG4T";
        String salt = "12345678";
        String iteration = "230";

        String storeFileName = getStoragePathForNewFile();

        String[] args = { "--location=" + storeFileName, "--create", "--add", "testalias", "--secret",
                "secret2", "--summary", "--password", clearTextPassword, "--salt", salt, "--iteration", iteration };

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.contains(expectedMaskedPassword + ";" + salt + ";" + iteration));
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1035")
    public void testMutuallyExclusiveArgs() {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String clearTextPassword = "secret_password";

        Pair<String, String> addOperation = Pair.of("--add", "-a");
        Pair<String, String> existsOperation = Pair.of("--exists", "-e");
        Pair<String, String> removeOperation = Pair.of("--remove", "-r");
        Pair<String, String> aliasesOperation = Pair.of("--aliases", "-v");

        String storeFileName = getStoragePathForNewFile();
        String[] firstOperation = { addOperation.getLeft(), addOperation.getRight(), existsOperation.getLeft(),
                aliasesOperation.getLeft(), aliasesOperation.getRight() };
        String[] secondOperation = { removeOperation.getRight(), removeOperation.getLeft(), addOperation.getLeft(),
                removeOperation.getLeft(), addOperation.getRight() };

        for (int i = 0; i < firstOperation.length; i++) {
            String[] args = { "--location=" + storeFileName, "--create", firstOperation[i],
                    "testalias", "--secret", "secret2", "--summary", "--password", clearTextPassword,
                    secondOperation[i] };
            try {
                command.execute(args);
                Assert.fail("We expect fail.");
            } catch (Exception e) {
                if (!(e instanceof AlreadySelectedException)) {
                    Assert.fail(String.format("We expect different exception [%s], but we get [%s]",
                        AlreadySelectedException.class.getSimpleName(), e.getClass().getSimpleName()));
                }
                assertEquals(
                    String.format("The option '%s' was specified but an option from this group has already been selected: '%s'",
                        secondOperation[i], firstOperation[i]), e.getMessage());
            }
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1036")
    public void testMultiRequiredOption() {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND);

        String clearTextPassword = "secret_password";

        String storeFileName = getStoragePathForNewFile();
        String longOperation = "add";
        String shortOperation = "a";

        String[] args = { "--location=" + storeFileName, "--create", "--" + longOperation, "testalias",
                "--secret", "secret2", "--summary", "--password", clearTextPassword, "-" + shortOperation, "doesnt_matter" };
        try {
            command.execute(args);
            Assert.fail("We expect fail.");
        } catch (Exception e) {
            if (!(e instanceof AlreadySelectedException)) {
                Assert.fail(String.format("We expect different exception [%s], but we get [%s]",
                    AlreadySelectedException.class.getSimpleName(), e.getClass().getSimpleName()));
            }
            assertEquals(
                String.format("FIX THIS CONDITION once the bug is fixed. '%s', '%s'", shortOperation, longOperation),
                e.getMessage());
        }
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1037"
    + "https://issues.jboss.org/browse/ELY-890")
    public void testLocationFromUri() {
        String clearTextPassword = "secret_password";
        String aliasName = "aliasName";

        String storeFileName = "test.jceks";
        String longOperation = "add";

        String[] args = { "--uri=cr-store://" + storeFileName + "?create=true", "--" + longOperation, aliasName,
                "--secret", "secret2", "--summary", "--password", clearTextPassword };

        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storeFileName, clearTextPassword);
        checkExistsAlias(store, aliasName);
    }

    @Test
    public void testPrintHelp() {
        String clearTextPassword = "secret_password";
        String storeFileName = getStoragePathForNewFile();
        assertTrue(executeCommandAndCheckStatusAndGetOutput(new String[]{"--help",  "--location=" + storeFileName, "--create", "--summary", "--password", clearTextPassword, "-a", "alias1", "-x", "secret1" })
            .contains("Get help with usage of this command"));
        assertTrue(executeCommandAndCheckStatusAndGetOutput(new String[]{"--help"})
                .contains("Get help with usage of this command"));

    }

    @Test
    @Ignore("https://issues.jboss.org/browse/ELY-1033")
    public void testShowHelpWithPriority() {
        String clearTextPassword = "secret_password";

        String storeFileName = getStoragePathForNewFile();

        String[] args = { "--location=" + storeFileName, "--create", "--add", "testalias", "--secret",
                "secret2", "--summary", "--password", clearTextPassword, "--help" };

        String output = executeCommandAndCheckStatusAndGetOutput(args);
        assertTrue(output.contains("Get help with usage of this command"));
    }

    @Test
    @Ignore("https://issues.jboss.org/browse/WFCORE-2480")
    public void testCreateEmptyStore() {
        String clearTextPassword = "secret_password";
        String aliasName = "aliasName";

        String storeFileName = getStoragePathForNewFile();
        String longOperation = "create-storage";

        String[] args = { "--uri=cr-store://" + storeFileName + "?create=true", "--" + longOperation, "--summary", "--password",
                clearTextPassword };

        executeCommandAndCheckStatus(args);

        CredentialStore store = getCredentialStoreStorageFromExistsFile(storeFileName, clearTextPassword);
        // write alias to store... (if backed file exists it will pass)
        try {
            store.store(aliasName, createCredentialFromPassword("aliasSecretValue".toCharArray()));
            store.flush();
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void testDuplicateOptions() {
        String storageLocation = getStoragePathForNewFile();
        String storagePassword = "cspassword";
        String aliasName = "testalias";
        String aliasValue = "secret2";

        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret", aliasValue, "--summary",
                "--password", storagePassword, "--add", "another_alias", "-x", "another_secret" };
        String output = executeCommandAndCheckStatusAndGetOutput(args);

        Assert.assertTrue(output.contains("Option \"add\" specified more than once. Only the first occurrence will be used."));
        Assert.assertTrue(output.contains("Option \"secret\" specified more than once. Only the first occurrence will be used."));
        Assert.assertFalse(output.contains("Option \"create\" specified more than once. Only the first occurrence will be used"));
    }

    private boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().startsWith("windows");
    }
}
