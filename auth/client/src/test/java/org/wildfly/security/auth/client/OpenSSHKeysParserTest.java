/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;


import java.io.File;
import java.net.URI;
import java.net.URL;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SSHCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.WildFlyElytronCredentialStoreProvider;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * Tests parsing KeyPairs specified as OpenSSH formatted private keys.
 *
 *  @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */
public class OpenSSHKeysParserTest {

    public static final String RSA_ALGORITHM = "RSA";
    public static final String DSA_ALGORITHM = "DSA";
    public static final String EC_ALGORITHM = "EC";
    private static final Provider CREDENTIAL_STORE_PROVIDER = new WildFlyElytronCredentialStoreProvider();

    private static final char[] CREDENTIAL_STORE_PASSWORD = "Elytron".toCharArray();
    private static final char[] KEY_PASSPHRASE = "secret".toCharArray();

    private static Map<String, String> stores = new HashMap<>();
    private static String BASE_STORE_DIRECTORY = "target/ks-cred-stores";
    static {
        stores.put("ONE", BASE_STORE_DIRECTORY + "/openssh-keys-test.jceks");
    }

    private static void cleanCredentialStores() {
        File dir = new File(BASE_STORE_DIRECTORY);
        dir.mkdirs();

        for (String f: stores.values()) {
            File file = new File(f);
            file.delete();
        }
    }

    static final class Data {
        private String alias;
        private Credential credential;
        private CredentialStore.ProtectionParameter protectionParameter;

        Data(final String alias, final Credential credential, final CredentialStore.ProtectionParameter protectionParameter) {
            this.alias = alias;
            this.credential = credential;
            this.protectionParameter = protectionParameter;
        }

        String getAlias() {
            return alias;
        }

        Credential getCredential() {
            return credential;
        }

        CredentialStore.ProtectionParameter getProtectionParameter() {
            return protectionParameter;
        }
    }

    @BeforeClass
    public static void setUp() throws Exception {
        Security.insertProviderAt(CREDENTIAL_STORE_PROVIDER, 1);

        cleanCredentialStores();
        String file = stores.get("ONE");
        String type = "JCEKS";
        ArrayList<Data> data = new ArrayList<>();
        Credential credential = new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, KEY_PASSPHRASE));
        data.add(new Data("alias", credential, null));
        if (file == null) {
            throw new IllegalStateException("file has to be specified");
        }

        KeyStoreCredentialStore storeImpl = new KeyStoreCredentialStore();

        final Map<String, String> map = new HashMap<>();
        map.put("location", file);
        map.put("create", Boolean.TRUE.toString());
        if (type != null) map.put("keyStoreType", type);
        storeImpl.initialize(
                map,
                new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, CREDENTIAL_STORE_PASSWORD)))),
                null
        );

        for (Data item : data) {
            storeImpl.store(item.getAlias(), item.getCredential(), item.getProtectionParameter());
        }
        storeImpl.flush();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        Security.removeProvider(CREDENTIAL_STORE_PROVIDER.getName());
    }

    @Test
    public void testOpenSSHRSAParsing() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-openssh-keys.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("ssh://rsa/"), null, null);
        Assert.assertNotNull(node);
        KeyPair keyPair = node.getConfiguration().getCredentialSource().getCredential(KeyPairCredential.class).getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(RSA_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(RSA_ALGORITHM, keyPair.getPublic().getAlgorithm());

    }

    @Test
    public void testOpenSSHDSAParsing() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-openssh-keys.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("ssh://dsa/"), null, null);
        Assert.assertNotNull(node);
        KeyPair keyPair = node.getConfiguration().getCredentialSource().getCredential(KeyPairCredential.class).getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(DSA_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(DSA_ALGORITHM, keyPair.getPublic().getAlgorithm());

    }

    @Test
    public void testOpenSSHECDSAParsing() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-openssh-keys.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("ssh://ecdsa/"), null, null);
        Assert.assertNotNull(node);
        KeyPairCredential credential = node.getConfiguration().getCredentialSource().getCredential(KeyPairCredential.class);
        KeyPair keyPair = credential.getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPublic().getAlgorithm());

    }

    @Test
    public void testOpenSSHECDSAMaskedPwdParsing() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-openssh-keys.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("ssh://ecdsa-masked-pwd/"), null, null);
        Assert.assertNotNull(node);
        KeyPair keyPair = node.getConfiguration().getCredentialSource().getCredential(KeyPairCredential.class).getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPublic().getAlgorithm());

    }

    @Test
    public void testOpenSSHECDSACredStoreRefParsing() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-openssh-keys.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("ssh://ecdsa-cred-store-ref/"), null, null);
        Assert.assertNotNull(node);
        KeyPair keyPair = node.getConfiguration().getCredentialSource().getCredential(KeyPairCredential.class).getKeyPair();
        Assert.assertNotNull(keyPair);
        Assert.assertNotNull(keyPair.getPrivate());
        Assert.assertNotNull(keyPair.getPublic());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPrivate().getAlgorithm());
        Assert.assertEquals(EC_ALGORITHM, keyPair.getPublic().getAlgorithm());

    }

    @Test
    public void testOpenSSHCredentialDefaultParsing() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-openssh-keys.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("ssh://ssh-credential-default/"), null, null);
        Assert.assertNotNull(node);
        SSHCredential credential = node.getConfiguration().getCredentialSource().getCredential(SSHCredential.class);
        Assert.assertEquals(SSHCredential.DEFAULT_SSH_DIRECTORY, credential.getSshDirectory());
        Assert.assertTrue(credential.getPrivateKeyIdentities().length == SSHCredential.DEFAULT_PRIVATE_KEYS.length);
        Assert.assertEquals(SSHCredential.DEFAULT_PRIVATE_KEYS[0], credential.getPrivateKeyIdentities()[0]);
        Assert.assertEquals(SSHCredential.DEFAULT_KNOWN_HOSTS, credential.getKnownHostsFile());
        String password = new String(credential.getPassphrase().castAndApply(PasswordCredential.class, c -> c.getPassword()).castAndApply(ClearPassword.class, ClearPassword::getPassword));
        Assert.assertEquals("secret", password);

    }

    @Test
    public void testOpenSSHCredentialParsing() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-openssh-keys.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("ssh://ssh-credential/"), null, null);
        Assert.assertNotNull(node);
        SSHCredential credential = node.getConfiguration().getCredentialSource().getCredential(SSHCredential.class);
        Assert.assertEquals(Paths.get("user", "home","test", ".ssh").toFile().getName(), credential.getSshDirectory().getName());
        Assert.assertTrue(credential.getPrivateKeyIdentities().length == 1);
        Assert.assertEquals("id_test_ecdsa", credential.getPrivateKeyIdentities()[0]);
        Assert.assertEquals("known_hosts_test", credential.getKnownHostsFile());
        String password = new String(credential.getPassphrase().castAndApply(PasswordCredential.class, c -> c.getPassword()).castAndApply(ClearPassword.class, ClearPassword::getPassword));
        Assert.assertEquals("secret", password);

    }
}
