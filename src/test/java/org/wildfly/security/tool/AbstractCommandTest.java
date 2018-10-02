/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.security.tool;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Random;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

public abstract class AbstractCommandTest extends BaseToolTest {

    /**
     * temporary folder
     */
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final Random random = new Random();

    public AbstractCommandTest() {
        super();
    }

    protected abstract String getCommandType();

    protected String getStoragePathForNewFile() {
        Path path;
        do {
            path = Paths.get(tmp.getRoot().getAbsolutePath(), "/test_" + random.nextInt() + ".store");
        } while (Files.exists(path));

        return path.toAbsolutePath().toString();
    }

    protected void executeCommandAndCheckStatus(String commandType, String[] args) {
        executeCommandAndCheckStatus(commandType, args, ElytronTool.ElytronToolExitStatus_OK);
    }

    protected void executeCommandAndCheckStatus(String[] args, int expectedReturnCode) {
        executeCommandAndCheckStatus(null, args, expectedReturnCode);
    }

    protected void executeCommandAndCheckStatus(String commandType, String[] args, int expectedReturnCode) {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(commandType == null ? getCommandType() : commandType);
        try {
            command.execute(args);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        assertEquals("returned command status has to be " + expectedReturnCode, expectedReturnCode, command.getStatus());
    }

    protected void executeCommandAndCheckStatus(String[] args) {
        executeCommandAndCheckStatus(null, args);
    }

    protected String executeCommandAndCheckStatusAndGetOutput(String commandType, String[] args) {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(commandType == null ? getCommandType() : commandType);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        PrintStream original = System.out;
        System.setOut(new PrintStream(result));
        try {
            command.execute(args);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.setOut(original);
        System.out.println("result" + result.toString());
        assertEquals("returned command status has to be 0", command.getStatus(), ElytronTool.ElytronToolExitStatus_OK);
        return result.toString();
    }

    protected String executeCommandAndCheckStatusAndGetOutput(String[] args) {
        return executeCommandAndCheckStatusAndGetOutput(null, args, ElytronTool.ElytronToolExitStatus_OK);
    }

    protected String executeCommandAndCheckStatusAndGetOutput(String[] args, int expectedReturnCode) {
        return executeCommandAndCheckStatusAndGetOutput(null, args, expectedReturnCode);
    }

    protected String executeCommandAndCheckStatusAndGetOutput(String commandType, String[] args, int expectedReturnCode) {
        ElytronTool tool = new ElytronTool();
        Command command = tool.findCommand(commandType == null ? getCommandType() : commandType);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        PrintStream original = System.out;
        System.setOut(new PrintStream(result));
        try {
            command.execute(args);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.setOut(original);
        System.out.println("result" + result.toString());
        assertEquals("returned command status has to be " + expectedReturnCode, expectedReturnCode, command.getStatus());
        return result.toString();
    }

    protected void checkAliasSecretValue(CredentialStore cs, String aliasName, String secretValue) {
        String storedSecretValue = getSecretValue(cs, aliasName);
        if (storedSecretValue != null) {
            assertEquals(String.format("Wrong secret value for alias [%s]", aliasName), secretValue, storedSecretValue);
        } else {
            Assert.fail(String.format("No secret value for alias: [%s]", aliasName));
        }
    }

    protected void checkNonExistsAlias(CredentialStore cs, String aliasName) {
        if (existsAlias(cs, aliasName)) {
            Assert.fail(String.format("Alias [%s] must not exist in storage.", aliasName));
        }
    }

    protected void checkExistsAlias(CredentialStore cs, String aliasName) {
        if (!existsAlias(cs, aliasName)) {
            Assert.fail(String.format("Alias with name [%s] isn't stored in storage.", aliasName));
        }
    }

    protected boolean existsAlias(CredentialStore cs, String aliasName) {
        return getSecretValue(cs, aliasName) != null;
    }

    protected String getSecretValue(CredentialStore cs, String aliasName) {
        PasswordFactory passwordFactory;
        try {
            passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
            final PasswordCredential retrievedCredential = cs.retrieve(aliasName, PasswordCredential.class);
            if (retrievedCredential != null) {
                final ClearPasswordSpec retrievedPassword = passwordFactory.getKeySpec(retrievedCredential.getPassword(),
                    ClearPasswordSpec.class);
                if (retrievedPassword != null && retrievedPassword.getEncodedPassword() != null) {
                    return new String(retrievedPassword.getEncodedPassword());
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | CredentialStoreException e) {
            throw new RuntimeException();
        }
        return null;
    }

    protected CredentialStore getCredentialStoreStorageFromExistsFile(String location, String password) {
        return getCredentialStore(location, password, false);
    }

    protected CredentialStore getCredentialStore(String location, String password, boolean createStorage) {
        HashMap<String, String> csAttributes = new HashMap<>();

        csAttributes.put("location", location);
        csAttributes.put("keyStoreType", "JCEKS");
        csAttributes.put("create", Boolean.valueOf(createStorage).toString());

        CredentialStore cs;
        try {
            cs = newCredentialStoreInstance();
            cs.initialize(csAttributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword(password.toCharArray()))));
        } catch (NoSuchAlgorithmException | CredentialStoreException e) {
            throw new RuntimeException();
        }
        return cs;
    }

    private static CredentialStore newCredentialStoreInstance() throws NoSuchAlgorithmException {
        return CredentialStore.getInstance(KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE);
    }

    protected PasswordCredential createCredentialFromPassword(char[] password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }

    protected void createStoreAndAddAliasAndCheck(String storageLocation, String storagePassword, String aliasName,
        String aliasValue) {
        String[] args = { "--location=" + storageLocation, "--create", "--add", aliasName, "--secret",
                aliasValue, "--summary", "--password", storagePassword };
        executeCommandAndCheckStatus(args);
        CredentialStore store = getCredentialStoreStorageFromExistsFile(storageLocation, storagePassword);
        checkAliasSecretValue(store, aliasName, aliasValue);
    }
}