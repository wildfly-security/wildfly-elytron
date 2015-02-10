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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.ClientCallbackHandler;
import org.wildfly.security.sasl.util.HexConverter;

/**
 * Test of client side of the Digest mechanism.
 * JMockit ensure same generated nonce in every test run.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class CompatibilityClientTest extends BaseTestCase {

    protected static final String DIGEST = "DIGEST-MD5";
    protected static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
    protected static final String QOP_PROPERTY = "javax.security.sasl.qop";

    private SaslClient client;

    private void mockNonce(final String nonce){
        new MockUp<AbstractDigestMechanism>(){
            @Mock
            byte[] generateNonce(){
                return nonce.getBytes();
            }
        };
    }

    /**
     * Test communication by first example in RFC 2831 [page 18]
     */
    @Test
    public void testRfc2831example1() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
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
     */
    @Test
    public void testRfc2831example2() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "acap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
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
     */
    @Test
    public void testAuthorizedAuthorizationId() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
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
     */
    @Test
    public void testQopAuthInt() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-int");
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

        byte[] outcoming1 = HexConverter.convertFromHex("11223344");
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("1122334499191be7952a49d8549b000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming1 = HexConverter.convertFromHex("55667788cf5e02ad15987d9076b8000100000000");
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming2 = HexConverter.convertFromHex("aabbcc");
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("aabbcc7e845ed48b0474447543000100000001", HexConverter.convertToHexString(outcoming2wrapped));

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", HexConverter.convertToHexString(incoming2unwrapped));

        // MAC not corresponds to message and sequence number
        byte[] incoming3 = HexConverter.convertFromHex("016603ce7148b6869e1b8df557000100000001");
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("01020352873023be5e875d6a93000100000002");
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=default=3des)
     */
    @Test
    public void testQopAuthConf() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
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

        byte[] outcoming1 = HexConverter.convertFromHex("11223344");
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("13f7644f8c783501177522c1a455cb1f000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming1 = HexConverter.convertFromHex("93ce33409e0fe5187e07c16fc3041f64000100000000");
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming2 = HexConverter.convertFromHex("aabbcc");
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("ec426d9cd3276f22285ab5da8df8f26b000100000001", HexConverter.convertToHexString(outcoming2wrapped));

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", HexConverter.convertToHexString(incoming2unwrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("cb8905522a50046ecb969c11a9d72014000100000001");
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("b12efd35ef3289f98cf6d98e6547bd3a000100000002");
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4)
     */
    @Test
    public void testQopAuthConfRc4() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
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

        byte[] outcoming1 = HexConverter.convertFromHex("11223344");
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("6a9328ca634e47c8d1ecc3c3f6e6000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming1 = HexConverter.convertFromHex("9fc7eb1c3c9e04b52df6e347a389000100000000");
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming2 = HexConverter.convertFromHex("aabbcc");
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("7e15b940fccbb58a5612f54da7000100000001", HexConverter.convertToHexString(outcoming2wrapped));

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", HexConverter.convertToHexString(incoming2unwrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("b0d829402149855796493cdf21000100000001");
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("a5a7390698ed8ab7ac667406a3000100000002");
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=des)
     */
    @Test
    public void testQopAuthConfDes() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
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

        byte[] outcoming1 = HexConverter.convertFromHex("11223344");
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("b2a12ba8ccd1030e7da4bac57a224197000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming1 = HexConverter.convertFromHex("8bc1267e71a769456f0c60f030e13f32000100000000");
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming2 = HexConverter.convertFromHex("aabbcc");
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("13144fc90ca65d3838d3547cca43e8ad000100000001", HexConverter.convertToHexString(outcoming2wrapped));

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", HexConverter.convertToHexString(incoming2unwrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("54d717857f511fb1964a723e08bf810c000100000001");
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("44dd10b5277ee6c7de87cd0c3acacfad000100000002");
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-56)
     */
    @Test
    public void testQopAuthConfRc456() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
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

        byte[] outcoming1 = HexConverter.convertFromHex("11223344");
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("7a77c4b8b20208e502e5dc09bbfc000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming1 = HexConverter.convertFromHex("c10acbf737cdebf2298df53417bc000100000000");
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming2 = HexConverter.convertFromHex("aabbcc");
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("efcb8662925427788b0ffeab2c000100000001", HexConverter.convertToHexString(outcoming2wrapped));

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", HexConverter.convertToHexString(incoming2unwrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("b18150d7204da90f0f733e3f73000100000001");
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("ed5cc6b9058c9e5f3a175cdcbf000100000002");
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-40)
     */
    @Test
    public void testQopAuthConfRc440() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
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

        byte[] outcoming1 = HexConverter.convertFromHex("11223344");
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("ed46c6b0d38acb719aad661f9625000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming1 = HexConverter.convertFromHex("44aca6145a89353d26258e524724000100000000");
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        assertEquals("55667788", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming2 = HexConverter.convertFromHex("aabbcc");
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("b7bdc8f08733182154289e7f3d000100000001", HexConverter.convertToHexString(outcoming2wrapped));

        byte[] incoming2 = new byte[0];
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        assertEquals("", HexConverter.convertToHexString(incoming2unwrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("685082d4671e03ac60df93d1b9000100000001");
        byte[] incoming3unwrapped = client.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("c7b5198826c7066b48e474db0c000100000002");
            client.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=unknown)
     */
    @Test
    public void testQopAuthConfUnknown() throws Exception {
        mockNonce("OA9BSuZWMSpW8m");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
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
     */
    @Test
    public void testMoreRealmsFromServer() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray(), "elwood.innosoft.com");
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
     */
    @Test
    public void testNoRealmsFromServer() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
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
     */
    @Test
    public void testNoServerNonce() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
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
     */
    @Test
    public void testBlankServerNonce() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
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
     */
    @Test
    @Ignore("Problem with encoding on Windows")
    public void testUtf8Charset() throws Exception {
        mockNonce("cn\u0438\u4F60\uD83C\uDCA1");

        CallbackHandler clientCallback = new ClientCallbackHandler("\u0438\u4F60\uD83C\uDCA1", "\u0438\u4F60\uD83C\uDCA1".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "\u0438\u4F60\uD83C\uDCA1", "realm.\u0438\u4F60\uD83C\uDCA1.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"realm.\u0438\u4F60\uD83C\uDCA1.com\",nonce=\"sn\u0438\u4F60\uD83C\uDCA1\",charset=utf-8,algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"\u0438\u4F60\uD83C\uDCA1\",realm=\"realm.\u0438\u4F60\uD83C\uDCA1.com\",nonce=\"sn\u0438\u4F60\uD83C\uDCA1\",nc=00000001,cnonce=\"cn\u0438\u4F60\uD83C\uDCA1\",digest-uri=\"\u0438\u4F60\uD83C\uDCA1/realm.\u0438\u4F60\uD83C\uDCA1.com\",maxbuf=65536,response=420939e06d2d748c157c5e33499b41a9,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=9c4d137545617ba98c11aaea939b4381".getBytes(StandardCharsets.UTF_8);
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test successful authentication with escaped realms delimiters
     */
    @Test
    public void testMoreRealmsWithEscapedDelimiters() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray(), "first realm");
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
     */
    @Test
    public void testWrongStepThreeRspauth() throws Exception {
        mockNonce("OA6MHXh6VqTrRk");

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
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
     */
    @Test
    public void testQopSelection1() throws Exception {
        mockNonce("+7HQhcJThEsqZ3gor1hThC5on8hQ3DRP2esrw+km");

        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf,auth-int,auth");

        CallbackHandler clientCallback = new ClientCallbackHandler("user", "password".toCharArray());
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
     */
    @Test
    public void testQopSelection2() throws Exception {
        mockNonce("a7YfTdcWo4L0OeurbYrT9G+01rZiNe6LSWuCSo73");

        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf,auth,auth-int");

        CallbackHandler clientCallback = new ClientCallbackHandler("user", "password".toCharArray());
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
     */
    @Test
    public void testQopSelectionFail() throws Exception {

        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");

        CallbackHandler clientCallback = new ClientCallbackHandler("user", "password".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[] { DIGEST }, "user", "TestProtocol", "TestServer", clientProps, clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"TestServer\",nonce=\"QduN0itdkfbx8VqlrWt56ZS7uRhI2Rt3P8bqfsM/\",qop=\"auth-int,auth\",charset=utf-8,algorithm=md5-sess".getBytes(StandardCharsets.UTF_8);
        try{
            client.evaluateChallenge(message1);
            fail("Not thrown SaslException!");
        } catch (SaslException e) {}
        assertFalse(client.isComplete());

    }
}