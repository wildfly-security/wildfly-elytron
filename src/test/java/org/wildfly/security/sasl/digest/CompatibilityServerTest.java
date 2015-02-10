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
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.ServerCallbackHandler;
import org.wildfly.security.sasl.util.HexConverter;

/**
 * Test of server side of the Digest mechanism.
 * JMockit ensure same generated nonce in every test run.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class CompatibilityServerTest extends BaseTestCase {

    protected static final String DIGEST = "DIGEST-MD5";
    protected static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
    protected static final String QOP_PROPERTY = "javax.security.sasl.qop";

    private SaslServer server;

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
        mockNonce("OA6MG9tEQGm2hh");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        server = Sasl.createSaslServer(DIGEST, "imap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",response=d388dad90d4bbd760a152321f2143af7,qop=auth".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=ea40f60335c427b5527b84dbabcdfffd", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

    }


    /**
     * Test communication by second example in RFC 2831 [page 19]
     */
    @Test
    public void testRfc2831example2() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",response=6084c6db3fede7352c551284490fd0fc,qop=auth".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=2f0b3d7c3c2e486600ef710726aa2eae", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

    }


    /**
     * Test with authorization ID (authzid) of other user
     */
    @Test
    public void testUnauthorizedAuthorizationId() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=0d071450228e395e2c0999e02b6aa665,qop=auth,authzid=\"george\"".getBytes(StandardCharsets.UTF_8);

        try {
            server.evaluateResponse(message2);
            fail("Not throwed SaslException!");
        } catch (SaslException e) {}
        assertFalse(server.isComplete());

    }


    /**
     * Test with authorization ID (authzid) - authorized
     */
    @Test
    public void testAuthorizedAuthorizationId() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",response=aa4e81f1c6656350f7bce05d436665de,qop=auth,authzid=\"chris\"".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);

        assertEquals("rspauth=af3ca83a805d4cfa00675a17315475c4", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

    }


    /**
     * Test with authentication plus integrity protection (qop=auth-int)
     */
    @Test
    public void testQopAuthInt() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        serverProps.put(QOP_PROPERTY, "auth-int");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-int\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=d8b17f55b410208c6ebb22f89f9d6cbb,qop=auth-int,authzid=\"chris\"".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=7a8794654d6d6de607e9143d52b554a8", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

        byte[] incoming1 = HexConverter.convertFromHex("1122334499191be7952a49d8549b000100000000");
        byte[] incoming1unwrapped = server.unwrap(incoming1, 0, incoming1.length);
        assertEquals("11223344", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming1 = HexConverter.convertFromHex("55667788");
        byte[] outcoming1wrapped = server.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("55667788cf5e02ad15987d9076b8000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming2 = HexConverter.convertFromHex("aabbcc7e845ed48b0474447543000100000001");
        byte[] incoming2unwrapped = server.unwrap(incoming2, 0, incoming2.length);
        assertEquals("aabbcc", HexConverter.convertToHexString(incoming2unwrapped));

        byte[] outcoming2 = new byte[0];
        byte[] outcoming2wrapped = server.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("", HexConverter.convertToHexString(outcoming2wrapped));

        // MAC not corresponds to message and sequence number
        byte[] incoming3 = HexConverter.convertFromHex("0188034ce1b414194c1c822a55000100000002");
        byte[] incoming3unwrapped = server.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("0102032cf12c67e4318ebd624e000100000003");
            server.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=default=3des)
     */
    @Test
    public void testQopAuthConf() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        serverProps.put(QOP_PROPERTY, "auth-conf");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"3des,rc4,des,rc4-56,rc4-40\",algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"3des\",authzid=\"chris\"".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=a804fda66588e2d911bbacd1b1163bc1", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

        byte[] incoming1 = HexConverter.convertFromHex("13f7644f8c783501177522c1a455cb1f000100000000");
        byte[] incoming1unwrapped = server.unwrap(incoming1, 0, incoming1.length);
        assertEquals("11223344", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming1 = HexConverter.convertFromHex("55667788");
        byte[] outcoming1wrapped = server.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("93ce33409e0fe5187e07c16fc3041f64000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming2 = HexConverter.convertFromHex("ec426d9cd3276f22285ab5da8df8f26b000100000001");
        byte[] incoming2unwrapped = server.unwrap(incoming2, 0, incoming2.length);
        assertEquals("aabbcc", HexConverter.convertToHexString(incoming2unwrapped));

        byte[] outcoming2 = new byte[0];
        byte[] outcoming2wrapped = server.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("", HexConverter.convertToHexString(outcoming2wrapped));

        // MAC not corresponds to message and sequence number
        byte[] incoming3 = HexConverter.convertFromHex("b0acad3c969d091251666f91070166f5000100000002");
        byte[] incoming3unwrapped = server.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("2cfa9bced5b960763953c4f9838b7022000100000003");
            server.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4)
     */
    @Test
    public void testQopAuthConfRc4() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        serverProps.put(QOP_PROPERTY, "auth-conf");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"3des,rc4,des,rc4-56,rc4-40\",algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4\",authzid=\"chris\"".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=a804fda66588e2d911bbacd1b1163bc1", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

        byte[] incoming1 = HexConverter.convertFromHex("6a9328ca634e47c8d1ecc3c3f6e6000100000000");
        byte[] incoming1unwrapped = server.unwrap(incoming1, 0, incoming1.length);
        assertEquals("11223344", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming1 = HexConverter.convertFromHex("55667788");
        byte[] outcoming1wrapped = server.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("9fc7eb1c3c9e04b52df6e347a389000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming2 = HexConverter.convertFromHex("7e15b940fccbb58a5612f54da7000100000001");
        byte[] incoming2unwrapped = server.unwrap(incoming2, 0, incoming2.length);
        assertEquals("aabbcc", HexConverter.convertToHexString(incoming2unwrapped));

        byte[] outcoming2 = new byte[0];
        byte[] outcoming2wrapped = server.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("", HexConverter.convertToHexString(outcoming2wrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("84468595614f4ac73fabe47cc4000100000002");
        byte[] incoming3unwrapped = server.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("4a206df4178a9b7d091dec3527000100000003");
            server.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=des)
     */
    @Test
    public void testQopAuthConfDes() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        serverProps.put(QOP_PROPERTY, "auth-conf");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"3des,rc4,des,rc4-56,rc4-40\",algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"des\",authzid=\"chris\"".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=a804fda66588e2d911bbacd1b1163bc1", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

        byte[] incoming1 = HexConverter.convertFromHex("b2a12ba8ccd1030e7da4bac57a224197000100000000");
        byte[] incoming1unwrapped = server.unwrap(incoming1, 0, incoming1.length);
        assertEquals("11223344", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming1 = HexConverter.convertFromHex("55667788");
        byte[] outcoming1wrapped = server.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("8bc1267e71a769456f0c60f030e13f32000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming2 = HexConverter.convertFromHex("13144fc90ca65d3838d3547cca43e8ad000100000001");
        byte[] incoming2unwrapped = server.unwrap(incoming2, 0, incoming2.length);
        assertEquals("aabbcc", HexConverter.convertToHexString(incoming2unwrapped));

        byte[] outcoming2 = new byte[0];
        byte[] outcoming2wrapped = server.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("", HexConverter.convertToHexString(outcoming2wrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("7022412985dbee1d261ecb8850486c6e000100000002");
        byte[] incoming3unwrapped = server.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("3457275b036fa15042e41aeda83a563b000100000003");
            server.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}
    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-56)
     */
    @Test
    public void testQopAuthConfRc456() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        serverProps.put(QOP_PROPERTY, "auth-conf");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"3des,rc4,des,rc4-56,rc4-40\",algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4-56\",authzid=\"chris\"".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=a804fda66588e2d911bbacd1b1163bc1", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

        byte[] incoming1 = HexConverter.convertFromHex("7a77c4b8b20208e502e5dc09bbfc000100000000");
        byte[] incoming1unwrapped = server.unwrap(incoming1, 0, incoming1.length);
        assertEquals("11223344", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming1 = HexConverter.convertFromHex("55667788");
        byte[] outcoming1wrapped = server.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("c10acbf737cdebf2298df53417bc000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming2 = HexConverter.convertFromHex("efcb8662925427788b0ffeab2c000100000001");
        byte[] incoming2unwrapped = server.unwrap(incoming2, 0, incoming2.length);
        assertEquals("aabbcc", HexConverter.convertToHexString(incoming2unwrapped));

        byte[] outcoming2 = new byte[0];
        byte[] outcoming2wrapped = server.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("", HexConverter.convertToHexString(outcoming2wrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("03c8fa9cb28ecf4a99561e5ac3000100000002");
        byte[] incoming3unwrapped = server.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("4daa261a6afb77f0b1d1d3d4eb000100000003");
            server.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-40)
     */
    @Test
    public void testQopAuthConfRc440() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        serverProps.put(QOP_PROPERTY, "auth-conf");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"3des,rc4,des,rc4-56,rc4-40\",algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4-40\",authzid=\"chris\"".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=a804fda66588e2d911bbacd1b1163bc1", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

        byte[] incoming1 = HexConverter.convertFromHex("ed46c6b0d38acb719aad661f9625000100000000");
        byte[] incoming1unwrapped = server.unwrap(incoming1, 0, incoming1.length);
        assertEquals("11223344", HexConverter.convertToHexString(incoming1unwrapped));

        byte[] outcoming1 = HexConverter.convertFromHex("55667788");
        byte[] outcoming1wrapped = server.wrap(outcoming1, 0, outcoming1.length);
        assertEquals("44aca6145a89353d26258e524724000100000000", HexConverter.convertToHexString(outcoming1wrapped));

        byte[] incoming2 = HexConverter.convertFromHex("b7bdc8f08733182154289e7f3d000100000001");
        byte[] incoming2unwrapped = server.unwrap(incoming2, 0, incoming2.length);
        assertEquals("aabbcc", HexConverter.convertToHexString(incoming2unwrapped));

        byte[] outcoming2 = new byte[0];
        byte[] outcoming2wrapped = server.wrap(outcoming2, 0, outcoming2.length);
        assertEquals("", HexConverter.convertToHexString(outcoming2wrapped));

        // bad message
        byte[] incoming3 = HexConverter.convertFromHex("34968ede3148eb0d3affe15656000100000002");
        byte[] incoming3unwrapped = server.unwrap(incoming3, 0, incoming3.length);
        assertEquals("", HexConverter.convertToHexString(incoming3unwrapped));

        // bad sequence number
        try {
            byte[] incoming4 = HexConverter.convertFromHex("8e497ee789076071cf3b5bb9e1000100000003");
            server.unwrap(incoming4, 0, incoming4.length);
            fail("Out of order sequencing SaslException expected!");
        } catch(SaslException e){}

    }


    /**
     * Replay attack (different nonce than sent by server)
     */
    @Test
    public void testReplayAttack() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",response=d388dad90d4bbd760a152321f2143af7,qop=auth".getBytes(StandardCharsets.UTF_8);
        try{
            server.evaluateResponse(message2);
            fail("Not throwed SaslException!");
        } catch (SaslException e) {
            assertTrue(e.getMessage().contains("nonce"));
        }
        assertFalse(server.isComplete());
    }


    /**
     * Bad response
     */
    @Test
    public void testBadResponse() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",response=d388dad90d4bbd760a152321f2143af7,qop=auth".getBytes(StandardCharsets.UTF_8);
        try{
            server.evaluateResponse(message2);
            fail("Not throwed SaslException!");
        } catch (SaslException e) {
            System.out.println(e.getMessage());
            assertTrue(e.getMessage().contains("response"));
        }
        assertFalse(server.isComplete());

    }


    /**
     * More realms from server (realm="other-realm",realm="elwood.innosoft.com",realm="next-realm" -> elwood.innosoft.com)
     */
    @Test
    public void testMoreRealmsFromServer() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "other-realm elwood.innosoft.com next-realm");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"other-realm\",realm=\"elwood.innosoft.com\",realm=\"next-realm\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",response=d388dad90d4bbd760a152321f2143af7,qop=auth".getBytes(StandardCharsets.UTF_8);
        try{
            server.evaluateResponse(message2);
            fail("Not throwed SaslException!");
        } catch (SaslException e) {}
        assertFalse(server.isComplete());

    }


    /**
     * Blank nonce from client (connection with naughty client)
     */
    @Test
    public void testBlankClientNonce() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "other-realm elwood.innosoft.com next-realm");
        server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"other-realm\",realm=\"elwood.innosoft.com\",realm=\"next-realm\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"\",digest-uri=\"acap/elwood.innosoft.com\",response=0ca21eafddf586f954909d2fd95b1ee7,qop=auth".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=2bf631e48acb9863e9f5518ccc804b3b", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

    }


    /**
     * Test successful authentication with Unicode chars (UTF-8 encoding)
     */
    @Test
    @Ignore("Problem with encoding on Windows")
    public void testUtf8Charset() throws Exception {
        mockNonce("sn\u0438\u4F60\uD83C\uDCA1");

        CallbackHandler serverCallback = new ServerCallbackHandler("\u0438\u4F60\uD83C\uDCA1", "\u0438\u4F60\uD83C\uDCA1".toCharArray());
        server = Sasl.createSaslServer(DIGEST, "\u0438\u4F60\uD83C\uDCA1", "realm.\u0438\u4F60\uD83C\uDCA1.com", new HashMap<String, Object>(), serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"realm.\u0438\u4F60\uD83C\uDCA1.com\",nonce=\"sn\u0438\u4F60\uD83C\uDCA1\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"\u0438\u4F60\uD83C\uDCA1\",realm=\"realm.\u0438\u4F60\uD83C\uDCA1.com\",nonce=\"sn\u0438\u4F60\uD83C\uDCA1\",nc=00000001,cnonce=\"cn\u0438\u4F60\uD83C\uDCA1\",digest-uri=\"\u0438\u4F60\uD83C\uDCA1/realm.\u0438\u4F60\uD83C\uDCA1.com\",maxbuf=65536,response=420939e06d2d748c157c5e33499b41a9,qop=auth".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=9c4d137545617ba98c11aaea939b4381", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("\u0438\u4F60\uD83C\uDCA1", server.getAuthorizationID());

    }


    /**
     * More realms from server (realm="other-realm",realm="elwood.innosoft.com",realm="next-realm" -> elwood.innosoft.com)
     */
    @Test
    public void testMoreRealmsWithEscapedDelimiters() throws Exception {
        mockNonce("OA9BSXrbuRhWay");

        CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "first\\ realm second\\\\\\ realm \\ with\\ spaces\\  \\ ");
        server = Sasl.createSaslServer(DIGEST, "protocol name", "server name", serverProps, serverCallback);
        assertFalse(server.isComplete());

        byte[] message1 = server.evaluateResponse(new byte[0]);
        assertEquals("realm=\"first realm\",realm=\"second\\\\ realm\",realm=\" with spaces \",realm=\" \",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
        assertFalse(server.isComplete());

        byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"first realm\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"protocol name/server name\",maxbuf=65536,response=bf3dd710ee08b05c663456975c156075,qop=auth".getBytes(StandardCharsets.UTF_8);
        byte[] message3 = server.evaluateResponse(message2);
        assertEquals("rspauth=05a18aff49b22e373bb91af7396ce345", new String(message3, "UTF-8"));
        assertTrue(server.isComplete());
        assertEquals("chris", server.getAuthorizationID());

    }

}