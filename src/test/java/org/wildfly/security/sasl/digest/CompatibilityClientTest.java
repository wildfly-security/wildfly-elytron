/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.digest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ClientUtils;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreBuilder;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

/**
 * Test of client side of the Digest mechanism.
 * JMockit ensure same generated nonce in every test run.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class CompatibilityClientTest extends BaseTestCase {

    /** mechanism name */
    protected static final String DIGEST = "DIGEST-MD5";
    /** QoP property name */
    protected static final String QOP_PROPERTY = "javax.security.sasl.qop";

    private SaslClient client;

    private void mockNonce(final String nonce){
        new MockUp<DigestSaslClient>(){
            @Mock
            byte[] generateNonce(){
                return nonce.getBytes(StandardCharsets.UTF_8);
            }
        };
    }

    private static String CS_FILE_NAME = "target/" + CompatibilityClientTest.class.getSimpleName() + ".cs";

    /**
     * Setup method to create required KeystorePassword for later use by tests.
     * @throws Exception if something goes wrong
     */
    @BeforeClass
    public static void setupCredentialStore() throws Exception {
        // setup credential store that need to be complete before a test starts
        CredentialStoreBuilder.get().setKeyStoreFile(CS_FILE_NAME)
                .setKeyStorePassword("secret_store_1")
                .addPassword("chris_pwd_alias", "secret")
                .build();
    }

    /**
     * Test communication by first example in RFC 2831 [page 18]
     * classic version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testRfc2831example1Classic() throws Exception {
        testRfc2831example1(false);
    }

    /**
     * Test communication by first example in RFC 2831 [page 18] using Credential Store
     * {@code CredentialStore} version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testRfc2831example1CredentialStore() throws Exception {
        testRfc2831example1(true);
    }


    /**
     * Test communication by first example in RFC 2831 [page 18]
     * @param useCredentialStore set to true to use CredentialStore
     * @throws Exception if something goes wrong
     */
    private void testRfc2831example1(boolean useCredentialStore) throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback;
        Map<String, Object> clientProps = new HashMap<>();
        if (useCredentialStore) {
            clientCallback = createCredentialStoreBasedClientCallbackHandler("chris", null, "chris_pwd_alias", CS_FILE_NAME, "secret_store_1", "secret_key_1");
        } else {
            clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        }
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, null, "imap", "elwood.innosoft.com", clientProps, clientCallback);
        assertNotNull(client);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=d388dad90d4bbd760a152321f2143af7,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=ea40f60335c427b5527b84dbabcdfffd".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test communication by second example in RFC 2831 [page 18]
     * classic version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testRfc2831example2Classic() throws Exception {
        testRfc2831example2(false);
    }

    /**
     * Test communication by second example in RFC 2831 [page 18]
     * {@code CredentialStore} version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testRfc2831example2CredentialStore() throws Exception {
        testRfc2831example2(true);
    }

    /**
     * Test communication by second example in RFC 2831 [page 18]
     * @param useCredentialStore set to true to use CredentialStore
     * @throws Exception if something goes wrong
     */
    private void testRfc2831example2(boolean useCredentialStore) throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback;
        Map<String, Object> clientProps = new HashMap<>();
        if (useCredentialStore) {
            clientCallback = createCredentialStoreBasedClientCallbackHandler("chris", null, "chris_pwd_alias", CS_FILE_NAME, "secret_store_1", "secret_key_1");
        } else {
            clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        }
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=6084c6db3fede7352c551284490fd0fc,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=2f0b3d7c3c2e486600ef710726aa2eae".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }

    /**
     * Test with authorization ID (authzid) - authorized
     * classic version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testAuthorizedAuthorizationIdClassic() throws Exception {
        testAuthorizedAuthorizationId(false);
    }

    /**
     * Test with authorization ID (authzid) - authorized
     * {@code CredentialStore} version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testAuthorizedAuthorizationIdCredentialStore() throws Exception {
        testAuthorizedAuthorizationId(true);
    }

    /**
     * Test with authorization ID (authzid) - authorized
     * @param useCredentialStore set to true to use CredentialStore
     * @throws Exception if something goes wrong
     */
    private void testAuthorizedAuthorizationId(boolean useCredentialStore) throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback;
        Map<String, Object> clientProps = new HashMap<>();
        if (useCredentialStore) {
            clientCallback = createCredentialStoreBasedClientCallbackHandler("chris", null, "chris_pwd_alias", CS_FILE_NAME, "secret_store_1", "secret_key_1");
        } else {
            clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        }
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=aa4e81f1c6656350f7bce05d436665de,qop=auth,authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=af3ca83a805d4cfa00675a17315475c4".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }

    /**
     * Test with authentication plus integrity protection (qop=auth-int)
     * classic version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthIntClassic() throws Exception {
        testQopAuthInt(false);
    }

    /**
     * Test with authentication plus integrity protection (qop=auth-int)
     * {@code CredentialStore} version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthIntCredentialStore() throws Exception {
        testQopAuthInt(true);
    }

    /**
     * Test with authentication plus integrity protection (qop=auth-int)
     * @param useCredentialStore set to true to use CredentialStore
     * @throws Exception if something goes wrong
     */
    private void testQopAuthInt(boolean useCredentialStore) throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback;
        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-int");
        if (useCredentialStore) {
            clientCallback = createCredentialStoreBasedClientCallbackHandler("chris", null, "chris_pwd_alias", CS_FILE_NAME, "secret_store_1", "secret_key_1");
        } else {
            clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        }
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-int\",charset=utf-8,algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=d8b17f55b410208c6ebb22f89f9d6cbb,qop=auth-int,authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=7a8794654d6d6de607e9143d52b554a8".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = CodePointIterator.ofString("11223344").hexDecode().drain();
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("1122334499191be7952a49d8549b000100000000", ByteIterator.ofBytes(outcoming1wrapped).hexEncode().drainToString());

        byte[] incoming1 = CodePointIterator.ofString("55667788cf5e02ad15987d9076b8000100000000").hexDecode().drain();
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", ByteIterator.ofBytes(incoming1unwrapped).hexEncode().drainToString());

        byte[] outcoming2 = CodePointIterator.ofString("aabbcc").hexDecode().drain();
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("aabbcc7e845ed48b0474447543000100000001", ByteIterator.ofBytes(outcoming2wrapped).hexEncode().drainToString());

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", ByteIterator.ofBytes(incoming2unwrapped).hexEncode().drainToString());

        // MAC not corresponds to message and sequence number
        byte[] incoming3 = CodePointIterator.ofString("016603ce7148b6869e1b8df557000100000001").hexDecode().drain();
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", ByteIterator.ofBytes(incoming3unwrapped).hexEncode().drainToString());

        // bad sequence number
        try {
            byte[] incoming4 = CodePointIterator.ofString("01020352873023be5e875d6a93000100000002").hexDecode().drain();
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=default=3des)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthConf() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"3des,rc4,des,rc4-56,rc4-40\",algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"3des\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = CodePointIterator.ofString("11223344").hexDecode().drain();
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("13f7644f8c783501177522c1a455cb1f000100000000", ByteIterator.ofBytes(outcoming1wrapped).hexEncode().drainToString());

        byte[] incoming1 = CodePointIterator.ofString("93ce33409e0fe5187e07c16fc3041f64000100000000").hexDecode().drain();
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", ByteIterator.ofBytes(incoming1unwrapped).hexEncode().drainToString());

        byte[] outcoming2 = CodePointIterator.ofString("aabbcc").hexDecode().drain();
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("ec426d9cd3276f22285ab5da8df8f26b000100000001", ByteIterator.ofBytes(outcoming2wrapped).hexEncode().drainToString());

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", ByteIterator.ofBytes(incoming2unwrapped).hexEncode().drainToString());

        // bad message
        byte[] incoming3 = CodePointIterator.ofString("cb8905522a50046ecb969c11a9d72014000100000001").hexDecode().drain();
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", ByteIterator.ofBytes(incoming3unwrapped).hexEncode().drainToString());

        // bad sequence number
        try {
            byte[] incoming4 = CodePointIterator.ofString("b12efd35ef3289f98cf6d98e6547bd3a000100000002").hexDecode().drain();
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4)
     * classic version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthConfRc4Classic() throws Exception {
        testQopAuthConfRc4(false);
    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4)
     * {@code CredentialStore} version
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthConfRc4CredentialStore() throws Exception {
        testQopAuthConfRc4(true);
    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4)
     * @param useCredentialStore set to true to use CredentialStore
     * @throws Exception if something goes wrong
     */
    private void testQopAuthConfRc4(boolean useCredentialStore) throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback;
        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        if (useCredentialStore) {
            clientCallback = createCredentialStoreBasedClientCallbackHandler("chris", null, "chris_pwd_alias", CS_FILE_NAME, "secret_store_1", "secret_key_1");
        } else {
            clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        }
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"rc4\",algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = CodePointIterator.ofString("11223344").hexDecode().drain();
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("6a9328ca634e47c8d1ecc3c3f6e6000100000000", ByteIterator.ofBytes(outcoming1wrapped).hexEncode().drainToString());

        byte[] incoming1 = CodePointIterator.ofString("9fc7eb1c3c9e04b52df6e347a389000100000000").hexDecode().drain();
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", ByteIterator.ofBytes(incoming1unwrapped).hexEncode().drainToString());

        byte[] outcoming2 = CodePointIterator.ofString("aabbcc").hexDecode().drain();
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("7e15b940fccbb58a5612f54da7000100000001", ByteIterator.ofBytes(outcoming2wrapped).hexEncode().drainToString());

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", ByteIterator.ofBytes(incoming2unwrapped).hexEncode().drainToString());

        // bad message
        byte[] incoming3 = CodePointIterator.ofString("b0d829402149855796493cdf21000100000001").hexDecode().drain();
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", ByteIterator.ofBytes(incoming3unwrapped).hexEncode().drainToString());

        // bad sequence number
        try {
            byte[] incoming4 = CodePointIterator.ofString("a5a7390698ed8ab7ac667406a3000100000002").hexDecode().drain();
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=des)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthConfDes() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"des\",algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"des\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = CodePointIterator.ofString("11223344").hexDecode().drain();
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("b2a12ba8ccd1030e7da4bac57a224197000100000000", ByteIterator.ofBytes(outcoming1wrapped).hexEncode().drainToString());

        byte[] incoming1 = CodePointIterator.ofString("8bc1267e71a769456f0c60f030e13f32000100000000").hexDecode().drain();
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", ByteIterator.ofBytes(incoming1unwrapped).hexEncode().drainToString());

        byte[] outcoming2 = CodePointIterator.ofString("aabbcc").hexDecode().drain();
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("13144fc90ca65d3838d3547cca43e8ad000100000001", ByteIterator.ofBytes(outcoming2wrapped).hexEncode().drainToString());

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", ByteIterator.ofBytes(incoming2unwrapped).hexEncode().drainToString());

        // bad message
        byte[] incoming3 = CodePointIterator.ofString("54d717857f511fb1964a723e08bf810c000100000001").hexDecode().drain();
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", ByteIterator.ofBytes(incoming3unwrapped).hexEncode().drainToString());

        // bad sequence number
        try {
            byte[] incoming4 = CodePointIterator.ofString("44dd10b5277ee6c7de87cd0c3acacfad000100000002").hexDecode().drain();
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-56)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthConfRc456() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"rc4-56\",algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4-56\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = CodePointIterator.ofString("11223344").hexDecode().drain();
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("7a77c4b8b20208e502e5dc09bbfc000100000000", ByteIterator.ofBytes(outcoming1wrapped).hexEncode().drainToString());

        byte[] incoming1 = CodePointIterator.ofString("c10acbf737cdebf2298df53417bc000100000000").hexDecode().drain();
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", ByteIterator.ofBytes(incoming1unwrapped).hexEncode().drainToString());

        byte[] outcoming2 = CodePointIterator.ofString("aabbcc").hexDecode().drain();
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("efcb8662925427788b0ffeab2c000100000001", ByteIterator.ofBytes(outcoming2wrapped).hexEncode().drainToString());

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", ByteIterator.ofBytes(incoming2unwrapped).hexEncode().drainToString());

        // bad message
        byte[] incoming3 = CodePointIterator.ofString("b18150d7204da90f0f733e3f73000100000001").hexDecode().drain();
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", ByteIterator.ofBytes(incoming3unwrapped).hexEncode().drainToString());

        // bad sequence number
        try {
            byte[] incoming4 = CodePointIterator.ofString("ed5cc6b9058c9e5f3a175cdcbf000100000002").hexDecode().drain();
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-40)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthConfRc440Classic() throws Exception {
        testQopAuthConfRc440(false);
    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-40)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthConfRc440CredentialStore() throws Exception {
        testQopAuthConfRc440(true);
    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-40)
     * @param useCredentialStore set to true to use CredentialStore
     * @throws Exception if something goes wrong
     */
    public void testQopAuthConfRc440(boolean useCredentialStore) throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback;
        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        if (useCredentialStore) {
            clientCallback = createCredentialStoreBasedClientCallbackHandler("chris", null, "chris_pwd_alias", CS_FILE_NAME, "secret_store_1", "secret_key_1");
        } else {
            clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        }
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"rc4-40\",algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4-40\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = CodePointIterator.ofString("11223344").hexDecode().drain();
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("ed46c6b0d38acb719aad661f9625000100000000", ByteIterator.ofBytes(outcoming1wrapped).hexEncode().drainToString());

        byte[] incoming1 = CodePointIterator.ofString("44aca6145a89353d26258e524724000100000000").hexDecode().drain();
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", ByteIterator.ofBytes(incoming1unwrapped).hexEncode().drainToString());

        byte[] outcoming2 = CodePointIterator.ofString("aabbcc").hexDecode().drain();
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("b7bdc8f08733182154289e7f3d000100000001", ByteIterator.ofBytes(outcoming2wrapped).hexEncode().drainToString());

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", ByteIterator.ofBytes(incoming2unwrapped).hexEncode().drainToString());

        // bad message
        byte[] incoming3 = CodePointIterator.ofString("685082d4671e03ac60df93d1b9000100000001").hexDecode().drain();
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", ByteIterator.ofBytes(incoming3unwrapped).hexEncode().drainToString());

        // bad sequence number
        try {
            byte[] incoming4 = CodePointIterator.ofString("c7b5198826c7066b48e474db0c000100000002").hexDecode().drain();
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=unknown)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopAuthConfUnknown() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"unknown\",algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        try{
            client.evaluateChallenge(message1);
            fail("Not thrown SaslException!");
        } catch (SaslException e) {}
        assertFalse(client.isComplete());

    }


    /**
     * More realms from server (realm="other-realm",realm="elwood.innosoft.com",realm="next-realm" -> elwood.innosoft.com)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testMoreRealmsFromServer() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), "elwood.innosoft.com");
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"other-realm\",realm=\"elwood.innosoft.com\",realm=\"next-realm\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=d388dad90d4bbd760a152321f2143af7,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=ea40f60335c427b5527b84dbabcdfffd".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * No realms from server
     * @throws Exception if something goes wrong
     */
    @Test
    public void testNoRealmsFromServer() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=695dcc815019923b9d438fd28c641aa9,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=ef0a550cd88d926ff426790bef156af3".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * No server nonce
     * @throws Exception if something goes wrong
     */
    @Test
    public void testNoServerNonce() throws Exception {

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        try{
            client.evaluateChallenge(message1);
            fail("Not thrown SaslException!");
        } catch (SaslException e) {}
        assertFalse(client.isComplete());

    }


    /**
     * Blank nonce from server (connection with naughty server)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testBlankServerNonce() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "nonce=\"\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",nonce=\"\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=c87a63a455fed82d007a7996d49a51bc,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=fa4e5be53f9b154858fb82d96c93a03a".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test successful authentication with Unicode chars (UTF-8 encoding)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testUtf8Charset() throws Exception {
        mockNonce("cn\u0438\u4F60\uD83C\uDCA1");

        CallbackHandler clientCallback = createClientCallbackHandler("\u0438\u4F60\uD83C\uDCA1", "\u0438\u4F60\uD83C\uDCA1".toCharArray(), null);
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "\u0438\u4F60\uD83C\uDCA1", "realm.\u0438\u4F60\uD83C\uDCA1.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"realm.\u0438\u4F60\uD83C\uDCA1.com\",nonce=\"sn\u0438\u4F60\uD83C\uDCA1\",charset=utf-8,algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"\u0438\u4F60\uD83C\uDCA1\",realm=\"realm.\u0438\u4F60\uD83C\uDCA1.com\",nonce=\"sn\u0438\u4F60\uD83C\uDCA1\",nc=00000001,cnonce=\"cn\u0438\u4F60\uD83C\uDCA1\",digest-uri=\"\u0438\u4F60\uD83C\uDCA1/realm.\u0438\u4F60\uD83C\uDCA1.com\",maxbuf=65536,response=420939e06d2d748c157c5e33499b41a9,qop=auth", new String(message2, StandardCharsets.UTF_8));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=9c4d137545617ba98c11aaea939b4381".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test successful authentication with escaped realms delimiters
     * @throws Exception if something goes wrong
     */
    @Test
    public void testMoreRealmsWithEscapedDelimiters() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), "first realm");
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "protocol name", "server name", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"first realm\",realm=\"second\\\\ realm\",realm=\" with spaces \",realm=\" \",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"first realm\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"protocol name/server name\",maxbuf=65536,response=bf3dd710ee08b05c663456975c156075,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=05a18aff49b22e373bb91af7396ce345".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test with wrong step three rspauth
     * @throws Exception if something goes wrong
     */
    @Test
    public void testWrongStepThreeRspauth() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=d388dad90d4bbd760a152321f2143af7,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=ab66f60335c427b5527b84dbabcdaacc".getBytes(StandardCharsets.UTF_8);
        try{
            client.evaluateChallenge(message3);
            fail("Not thrown SaslException!");
        } catch (SaslException e) {}
        assertFalse(client.isComplete());

    }


    /**
     * Test QOP selection by client (Server allow auth, auth-int, client want 1.auth-conf, 2.auth-int, 3.auth)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopSelection1() throws Exception {
        mockNonce("+7HQhcJThEsqZ3gor1hThC5on8hQ3DRP2esrw+km");

        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf,auth-int,auth");

        CallbackHandler clientCallback = createClientCallbackHandler("user", "password".toCharArray(), null);
        SaslClient client = Sasl.createSaslClient(new String[] { DIGEST }, "user", "TestProtocol", "TestServer", clientProps, clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"TestServer\",nonce=\"288HcNYUg60jN/kEFYT/HklRVjZA6opb2if8tsja\",qop=\"auth,auth-int\",charset=utf-8,algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"user\",realm=\"TestServer\",nonce=\"288HcNYUg60jN/kEFYT/HklRVjZA6opb2if8tsja\",nc=00000001,cnonce=\"+7HQhcJThEsqZ3gor1hThC5on8hQ3DRP2esrw+km\",digest-uri=\"TestProtocol/TestServer\",maxbuf=65536,response=663997cd2a9dc34c84240430fb1be16c,qop=auth-int,authzid=\"user\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=b3d6f9165b0bb0972adaa5778b840c3a".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test QOP selection by client (Server allow auth-int, auth, client want 1.auth-conf, 2.auth, 3.auth-int)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopSelection2() throws Exception {
        mockNonce("a7YfTdcWo4L0OeurbYrT9G+01rZiNe6LSWuCSo73");

        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf,auth,auth-int");

        CallbackHandler clientCallback = createClientCallbackHandler("user", "password".toCharArray(), null);
        SaslClient client = Sasl.createSaslClient(new String[] { DIGEST }, "user", "TestProtocol", "TestServer", clientProps, clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"TestServer\",nonce=\"QduN0itdkfbx8VqlrWt56ZS7uRhI2Rt3P8bqfsM/\",qop=\"auth-int,auth\",charset=utf-8,algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"user\",realm=\"TestServer\",nonce=\"QduN0itdkfbx8VqlrWt56ZS7uRhI2Rt3P8bqfsM/\",nc=00000001,cnonce=\"a7YfTdcWo4L0OeurbYrT9G+01rZiNe6LSWuCSo73\",digest-uri=\"TestProtocol/TestServer\",maxbuf=65536,response=636d1e3c3d73e1bfb15f85957720ce35,qop=auth,authzid=\"user\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a77854059f533745d50abb064b7df938".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test unsuccessful QOP selection by client (no common QOP)
     * @throws Exception if something goes wrong
     */
    @Test
    public void testQopSelectionFail() throws Exception {

        Map<String, Object> clientProps = new HashMap<>();
        clientProps.put(QOP_PROPERTY, "auth-conf");

        CallbackHandler clientCallback = createClientCallbackHandler("user", "password".toCharArray(), null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "user", "TestProtocol", "TestServer", clientProps, clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"TestServer\",nonce=\"QduN0itdkfbx8VqlrWt56ZS7uRhI2Rt3P8bqfsM/\",qop=\"auth-int,auth\",charset=utf-8,algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        try{
            client.evaluateChallenge(message1);
            fail("Not thrown SaslException!");
        } catch (SaslException e) {}
        assertFalse(client.isComplete());

    }

    /**
     * Test "stale" directive
     * Server MAY send a new "digest-challenge" with a new value for nonce.
     * Stale directive say whether should be old credential reused.
     */
    @Test
    public void testStaleNonce() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        Map<String, Object> clientProps = new HashMap<>();
        CallbackHandler clientCallback = createClientCallbackHandler("chris", "secret".toCharArray(), null);
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, null, "imap", "elwood.innosoft.com", clientProps, clientCallback);
        assertNotNull(client);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"tooOldNonce\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertFalse(client.isComplete());

        byte[] message3 = "stale=true,realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=d388dad90d4bbd760a152321f2143af7,qop=auth", new String(message4, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message5 = "rspauth=ea40f60335c427b5527b84dbabcdfffd".getBytes(StandardCharsets.UTF_8);
        byte[] message6 = client.evaluateChallenge(message5);
        assertEquals(null, message6);
        assertTrue(client.isComplete());
    }

    private CallbackHandler createClientCallbackHandler(String username, char[] password, String realm) throws Exception {
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .usePassword(password)
                                .useRealm(realm)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(SaslMechanismInformation.Names.DIGEST_MD5)));

        return ClientUtils.getCallbackHandler(new URI("doesnot://matter?"), context);
    }

    private CallbackHandler createCredentialStoreBasedClientCallbackHandler(String username, String realm, String alias, String storeFileName, String storePassword, String keyPassword)
            throws Exception {
        final HashMap<String, String> csAttributes = new HashMap<>();
        csAttributes.put("location", storeFileName);
        csAttributes.put("keyStoreType", "JCEKS");
        final CredentialStore cs;
        try {
            cs = CredentialStore.getInstance(KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE);
            cs.initialize(csAttributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, storePassword.toCharArray())))
            ));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        final AuthenticationContext context = AuthenticationContext.empty()
                .with(
                        MatchRule.ALL,
                        AuthenticationConfiguration.empty()
                                .useName(username)
                                .useCredentialStoreEntry(cs, alias)
                                .useRealm(realm)
                                .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism(SaslMechanismInformation.Names.DIGEST_MD5)));

        return ClientUtils.getCallbackHandler(new URI("doesnot://matter"), context);
    }

}