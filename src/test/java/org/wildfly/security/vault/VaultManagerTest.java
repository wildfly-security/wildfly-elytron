/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.vault;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.vault._private.PasswordLoaderBridge;
import org.wildfly.security.vault._private.VaultManager;
import org.wildfly.security.vault._private.VaultManagerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;


/**
 * {@code VaultManager} tests
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class VaultManagerTest {

    private static final Provider provider = new WildFlyElytronProvider();

    private static Map<String, String> VAULTS = new HashMap<>();
    private static String VAULTS_DIRECTORY = "target/vaults";
    static {
        VAULTS.put("ONE", VAULTS_DIRECTORY + "/vault_keystore.jceks");
        VAULTS.put("TWO", VAULTS_DIRECTORY + "/vaultKeystore2.jceks");
        VAULTS.put("THREE", VAULTS_DIRECTORY + "/vault-3.jceks");
    }

    /**
     * Clean all vaults.
     */
    public static void cleanVaults() {
        File dir = new File(VAULTS_DIRECTORY);
        dir.mkdirs();

        for (String f: VAULTS.values()) {
            File file = new File(f);
            file.delete();
        }
    }

    /**
     * Setup all need vaults by tests.
     * @throws IOException when problem occurs
     * @throws GeneralSecurityException when problem occurs
     */
    @BeforeClass
    public static void setupVaults() throws IOException, GeneralSecurityException {
        cleanVaults();
        // setup vaults that need to be complete before a test starts
        VaultBuilder.get().keyStoreFile(VAULTS.get("TWO"))
                .keyStorePasswords("secret_store_TWO", "secret_key_TWO")
                .data("alias1", "secret-password-1")
                .data("alias2", "secret-password-2")
                .build();
        VaultBuilder.get().keyStoreFile(VAULTS.get("THREE"))
                .keyStorePasswords("secret_store_THREE", "secret_key_THREE")
                .data("db-pass-1", "1-secret-info")
                .data("db-pass-2", "2-secret-info")
                .data("db-pass-3", "3-secret-info")
                .data("db-pass-4", "4-secret-info")
                .data("db-pass-5", "5-secret-info")
                .build();

    }

    /**
     * Register security provider containing {@link org.wildfly.security.storage.PasswordStorageSpi} implementation.
     */
    @BeforeClass
    public static void register() {
        Security.addProvider(provider);
    }

    /**
     * Remove security provider.
     */
    @AfterClass
    public static void remove() {
        Security.removeProvider(provider.getName());
    }

    /**
     * Basic vault manager test.
     * @throws Exception when problem occurs
     */
    @Test
    public void basicVaultManagerStoreTest() throws Exception {

        char[] password1 = "db-secret-pass1".toCharArray();
        char[] password2 = "PangmaŠišatá".toCharArray();
        char[] password3 = "Červenavý střizlíček a žľúva ďobali ve šťavnatých ocúnech".toCharArray();

        VaultManager vm = VaultManagerFactory.INSTANCE.getVaultManager();
        String testVaultUriBase = "vault://myvault";
        String testVaultUriDefinition = testVaultUriBase + "/" + VAULTS.get("ONE") + "?create.storage=true;storage.password='st_secret';key.password='key_secret'";
        String testVaultUriQuery1 = testVaultUriBase + "#db1-password1";
        String testVaultUriQuery2 = testVaultUriBase + "#db1-password2";
        String testVaultUriQuery3 = testVaultUriBase + "#db1-password3";

        vm.registerNewVaultInstance(new URI(testVaultUriDefinition), null, null, null);
        vm.store(testVaultUriQuery1, password1);
        vm.store(testVaultUriQuery2, password2);
        vm.store(testVaultUriQuery3, password3);

        Assert.assertArrayEquals(password2, vm.retrieve(testVaultUriQuery2));
        Assert.assertArrayEquals(password1, vm.retrieve(testVaultUriQuery1));
        Assert.assertArrayEquals(password3, vm.retrieve(testVaultUriQuery3));
    }

    /**
     * Basic vault test on already existing vault.
     * @throws Exception when problem occurs
     */
    @Test
    public void basicTestOnAlreadyCreatedVault() throws Exception {
        VaultManager vm = VaultManagerFactory.INSTANCE.getVaultManager();
        String testVaultUriBase = "vault://vault-two";
        String testVaultUriDefinition = testVaultUriBase + "/" + VAULTS.get("TWO") + "?storage.password='secret_store_TWO';key.password='secret_key_TWO'";
        String testVaultUriQuery1 = testVaultUriBase + "#alias1";
        String testVaultUriQuery2 = testVaultUriBase + "#alias2";

        vm.registerNewVaultInstance(new URI(testVaultUriDefinition), null, null, null);
        // expected entries there
        Assert.assertArrayEquals("secret-password-1".toCharArray(), vm.retrieve(testVaultUriQuery1));
        Assert.assertArrayEquals("secret-password-2".toCharArray(), vm.retrieve(testVaultUriQuery2));

        // retrieve non-existent entry
        try {
            vm.retrieve(testVaultUriBase + "#wrong_alias");
            Assert.fail("this part of code cannot be reached, retrieve() should throw VaultException");
        } catch (VaultException e) {
            // do nothing all is OK
        } catch (Throwable e) {
            Assert.fail("wrong exception thrown (" + e.getMessage() + ")");
        }

        // store test
        vm.store(testVaultUriBase + "#db-password", "supersecretdbpass".toCharArray());

        // remove test
        vm.remove(testVaultUriQuery2);

        if (!vm.exists(testVaultUriBase + "#db-password")) {
            Assert.fail(testVaultUriBase + "#db-password" + " has to exist");
        }

        if (vm.exists(testVaultUriQuery2)) {
            Assert.fail(testVaultUriQuery2 + " has been removed from the vault, but it exists");
        }
    }

    /**
     * Test for external password callback.
     * @throws Exception when problem occurs
     */
    @Test
    public void testExternalPasswordClassCallback() throws Exception {
        VaultManager vm = VaultManagerFactory.INSTANCE.getVaultManager();
        String testVaultUriBase = "vault://vault-3";
        String testVaultUriDefinition = testVaultUriBase + "/" + VAULTS.get("THREE") +
                "?callback=CLASS;" +
                "callback.passwordClass=org.wildfly.security.vault.TestExternalPasswordClass;" +
                "callback.myPassword='secret_store_THREE';" +   // this depends on implementation of PasswordClass (org.wildfly.security.vault.TestExternalPasswordClass)
                "key.password.callback=CLASS;" +
                "key.password.callback.passwordClass=org.wildfly.security.vault.TestExternalKeyPasswordClass;" +
                "key.password.callback.myPassword='secret_key_THREE'"    // this depends on implementation of PasswordClass (org.wildfly.security.vault.TestExternalPasswordClass)
                ;

        String testVaultUriQuery1 = testVaultUriBase + "#db-pass-1";
        String testVaultUriQuery2 = testVaultUriBase + "#db-pass-2";
        String testVaultUriQuery3 = testVaultUriBase + "#db-pass-3";
        String testVaultUriQuery4 = testVaultUriBase + "#db-pass-4";
        String testVaultUriQuery5 = testVaultUriBase + "#db-pass-5";
        String testVaultUriQueryWrongAttr = testVaultUriBase + "#db-pass-non-existent-attr";

        vm.registerNewVaultInstance(new URI(testVaultUriDefinition), null, null, null);
        // expected entries there
        Assert.assertArrayEquals("1-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery1));
        Assert.assertArrayEquals("2-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery2));
        Assert.assertArrayEquals("3-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery3));
        Assert.assertArrayEquals("4-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery4));
        Assert.assertArrayEquals("5-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery5));

        try {
            vm.retrieve(testVaultUriQueryWrongAttr);
            Assert.fail("retrieve is supposed to throw the VaultException when secured attribute doesn't exist in Vault");
        } catch (VaultException e) {
            // ignored for test purpose
        }
    }

    /**
     * External password class bridge test.
     * @throws Exception when problem occurs
     */
    @Test
    public void testExternalPasswordClassBridgeMethod() throws Exception {
        VaultManager vm = VaultManagerFactory.INSTANCE.getVaultManager();
        String testVaultUriBase = "//vault-3";
        String testVaultUriDefinition = testVaultUriBase + "/" + VAULTS.get("THREE") +
                "?storage.password='{CLASS}org.wildfly.security.vault.TestExternalPasswordClass';key.password='{CLASS}org.wildfly.security.vault.TestExternalKeyPasswordClass'";

        String testVaultUriQuery1 = VaultURIParser.VAULT_SCHEME + ":" + testVaultUriBase + "#db-pass-1";

        vm.registerNewVaultInstance(new URI(VaultURIParser.VAULT_SCHEME, testVaultUriDefinition, null), null, null, null);
        // expected entries there
        Assert.assertArrayEquals("1-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery1));
    }

    /**
     * External password class bridge test with parameters.
     * @throws Exception when problem occurs
     */
    @Test
    public void testExternalPasswordClassBridgeMethodWithParams() throws Exception {
        VaultManager vm = VaultManagerFactory.INSTANCE.getVaultManager();
        String testVaultUriBase = "//vault-3";
        String testVaultUriDefinition = testVaultUriBase + "/" + VAULTS.get("THREE") +
                "?storage.password='{CLASS}org.wildfly.security.vault.TestExternalPasswordClass:secret_store_THREE,5,123cc';key.password='{CLASS}org.wildfly.security.vault.TestExternalKeyPasswordClass:secret_key_THREE,3'";

        String testVaultUriQuery1 = VaultURIParser.VAULT_SCHEME + ":" + testVaultUriBase + "#db-pass-1";

        vm.registerNewVaultInstance(new URI(VaultURIParser.VAULT_SCHEME, testVaultUriDefinition, null), null, null, null);
        // expected entries there
        Assert.assertArrayEquals("1-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery1));
    }

    /**
     * External command callback test.
     * @throws Exception when problem occurs
     */
    @Test
    public void testExternalCommandCallback() throws Exception {

        String commandLineStorePassword = buildCommandLine(new String[]{"secret_store_THREE"});
        String commandLineKeyPassword = buildCommandLine(new String[]{"secret_key_THREE"});

        VaultManager vm = VaultManagerFactory.INSTANCE.getVaultManager();
        String testVaultUriBase = "//vault-3";
        String testVaultUriDefinition = testVaultUriBase + "/" + VAULTS.get("THREE") +
                "?" +
                "callback=EXT;" +
                "callback.command='" + commandLineStorePassword + "';" +
                "key.password.callback='EXT';" +
                "key.password.callback.command='" + commandLineKeyPassword + "'";

        String testVaultUriQuery1 = VaultURIParser.VAULT_SCHEME + ":" + testVaultUriBase + "#db-pass-1";

        vm.registerNewVaultInstance(new URI(VaultURIParser.VAULT_SCHEME, testVaultUriDefinition, null), null, null, null);
        // expected entries there
        Assert.assertArrayEquals("1-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery1));
    }

    /**
     * Masked password callback test.
     * @throws Exception when problem occurs
     */
    @Test
    public void testMaskedPasswordCallback() throws Exception {
        doMaskedPasswordCallbackTest("");
    }

    /**
     * Masked password test with prefix specified.
     * @throws Exception when problem occurs
     */
    @Test
    public void testMaskedPasswordCallbackWithPrefix() throws Exception {
        doMaskedPasswordCallbackTest(PasswordLoaderBridge.PASS_MASK_PREFIX);
    }

    private void doMaskedPasswordCallbackTest(String maskedPrefix) throws Exception {
        VaultManager vm = VaultManagerFactory.INSTANCE.getVaultManager();
        String testVaultUriBase = "//vault-3";
        String testVaultUriDefinition = testVaultUriBase + "/" + VAULTS.get("THREE") +
                "?" +
                "callback=MASKED;" +
                "callback.maskedPassword='" + maskedPrefix + "yYJrsYvFcLI8LMh/w6PYine8PjQ6fQXb';" +
                "callback.salt='WE12vw8g';" +
                "callback.iteration=33;" +
                "key.password.callback=MASKED;" +
                "key.password.maskedPassword='" + maskedPrefix + "YFdy4HVKQ36SzNd7lBmnFdxin4BdYUrm';" +
                "key.password.salt='XY12jk4r';" +
                "key.password.iteration=21";

        String testVaultUriQuery1 = VaultURIParser.VAULT_SCHEME + ":" + testVaultUriBase + "#db-pass-1";

        vm.registerNewVaultInstance(new URI(VaultURIParser.VAULT_SCHEME, testVaultUriDefinition, null), null, null, null);
        // expected entries there
        Assert.assertArrayEquals("1-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery1));
    }

    private String buildCommandLine(String[] args) {
        StringBuilder command = new StringBuilder(System.getProperty("java.home")).append("/bin/java ").append("-cp target/test-classes").append(' ');

        command.append(PasswordCommand.class.getName());

        for (String arg: args) {
            command.append(' ').append(arg);
        }

        return command.toString();
    }

    /**
     * Test for parametrized password callback.
     * @throws Exception when problem occurs
     */
    @Test
    public void testParametrizedCallbackHandler() throws Exception {
        VaultManager vm = VaultManagerFactory.INSTANCE.getVaultManager();
        String testVaultUriBase = "vault://vault-3";
        String testVaultUriDefinition = testVaultUriBase + "/" + VAULTS.get("THREE") +
                "?handler=org.wildfly.security.vault.TestParametrizedCallbackHandler;" +
                "callback=org.wildfly.security.vault.TestCallback;" +
                "callback.test.password='secret_store_THREE';" +  // this depends on implementation of org.wildfly.security.vault.TestParametrizedCallback)
                "key.password.callback.handler=org.wildfly.security.vault.TestParametrizedCallbackHandler;" +
                "key.password.callback=org.wildfly.security.vault.TestCallback;" +
                "key.password.callback.test.password='secret_key_THREE'"
                ;

        String testVaultUriQuery1 = testVaultUriBase + "#db-pass-1";
        String testVaultUriQuery2 = testVaultUriBase + "#db-pass-2";
        String testVaultUriQuery3 = testVaultUriBase + "#db-pass-3";
        String testVaultUriQuery4 = testVaultUriBase + "#db-pass-4";
        String testVaultUriQuery5 = testVaultUriBase + "#db-pass-5";
        String testVaultUriQueryWrongAttr = testVaultUriBase + "#db-pass-non-existent-attr";

        vm.registerNewVaultInstance(new URI(testVaultUriDefinition), null, null, null);
        // expected entries there
        Assert.assertArrayEquals("1-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery1));
        Assert.assertArrayEquals("2-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery2));
        Assert.assertArrayEquals("3-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery3));
        Assert.assertArrayEquals("4-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery4));
        Assert.assertArrayEquals("5-secret-info".toCharArray(), vm.retrieve(testVaultUriQuery5));

        try {
            vm.retrieve(testVaultUriQueryWrongAttr);
            Assert.fail("retrieve is supposed to throw the VaultException when secured attribute doesn't exist in Vault");
        } catch (VaultException e) {
            // ignored for test purpose
        }
    }

}
