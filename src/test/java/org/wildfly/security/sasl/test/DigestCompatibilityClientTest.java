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

package org.wildfly.security.sasl.test;

import static org.junit.Assert.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.jboss.byteman.contrib.bmunit.BMRule;
import org.jboss.byteman.contrib.bmunit.BMUnitRunner;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Test of client side of the Digest mechanism.
 * Byteman allow ensure same generated nonce in every test run.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(BMUnitRunner.class)
public class DigestCompatibilityClientTest extends BaseTestCase {

    //protected static final String NONCE_CLASS = "com.sun.security.sasl.digest.DigestMD5Base";
    protected static final String NONCE_CLASS = "org.wildfly.security.sasl.md5digest.AbstractMD5DigestMechanism";

    protected static final String DIGEST = "DIGEST-MD5";
    protected static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
    protected static final String QOP_PROPERTY = "javax.security.sasl.qop";

    private SaslClient client;

    /**
     * Test communication by first example in RFC 2831 [page 18]
     */
    @Test
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA6MHXh6VqTrRk\".getBytes();")
    public void testRfc2831example1() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=d388dad90d4bbd760a152321f2143af7,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=ea40f60335c427b5527b84dbabcdfffd".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test communication by second example in RFC 2831 [page 18]
     */
    @Test
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testRfc2831example2() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "acap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=6084c6db3fede7352c551284490fd0fc,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=2f0b3d7c3c2e486600ef710726aa2eae".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test with authorization ID (authzid) - authorized
     */
    @Test
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testAuthorizedAuthorizationId() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=aa4e81f1c6656350f7bce05d436665de,qop=auth,authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=af3ca83a805d4cfa00675a17315475c4".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * Test with authentication plus integrity protection (qop=auth-int)
     */
    @Test
    @Ignore("Integrity and privacy not implemented")
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthInt() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-int");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-int\",charset=utf-8,algorithm=md5-sess".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=d8b17f55b410208c6ebb22f89f9d6cbb,qop=auth-int,authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=7a8794654d6d6de607e9143d52b554a8".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = new byte[]{0x11,0x22,0x33,0x44};
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        Assert.assertArrayEquals(new byte[]{0x11,0x22,0x33,0x44,(byte)0x99,0x19,0x1b,(byte)0xe7,(byte)0x95,0x2a,0x49,(byte)0xd8,0x54,(byte)0x9b,0x00,0x01,0x00,0x00,0x00,0x00}, outcoming1wrapped);

        byte[] incoming1 = new byte[]{0x55,0x66,0x77,(byte)0x88,(byte)0xcf,0x5e,0x02,(byte)0xad,0x15,(byte)0x98,0x7d,(byte)0x90,0x76,(byte)0xb8,0x00,0x01,0x00,0x00,0x00,0x00};
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        Assert.assertArrayEquals(new byte[]{0x55,0x66,0x77,(byte)0x88}, incoming1unwrapped);

        byte[] outcoming2 = new byte[]{(byte)0xAA,(byte)0xBB,(byte)0xCC};
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        Assert.assertArrayEquals(new byte[]{(byte)0xaa,(byte)0xbb,(byte)0xcc,0x7e,(byte)0x84,0x5e,(byte)0xd4,(byte)0x8b,0x04,0x74,0x44,0x75,0x43,0x00,0x01,0x00,0x00,0x00,0x01}, outcoming2wrapped);

        byte[] incoming2 = new byte[]{};
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        Assert.assertArrayEquals(new byte[]{}, incoming2unwrapped);

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=default=3des)
     */
    @Test
    @Ignore("Integrity and privacy not implemented")
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthConf() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"3des,rc4,des,rc4-56,rc4-40\",algorithm=md5-sess".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"3des\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = new byte[]{0x11,0x22,0x33,0x44};
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        Assert.assertArrayEquals(new byte[]{0x13,(byte)0xf7,0x64,0x4f,(byte)0x8c,0x78,0x35,0x01,0x17,0x75,0x22,(byte)0xc1,(byte)0xa4,0x55,(byte)0xcb,0x1f,0x00,0x01,0x00,0x00,0x00,0x00}, outcoming1wrapped);

        byte[] incoming1 = new byte[]{(byte)0x93,(byte)0xce,0x33,0x40,(byte)0x9e,0x0f,(byte)0xe5,0x18,0x7e,0x07,(byte)0xc1,0x6f,(byte)0xc3,0x04,0x1f,0x64,0x00,0x01,0x00,0x00,0x00,0x00};
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        Assert.assertArrayEquals(new byte[]{0x55,0x66,0x77,(byte)0x88}, incoming1unwrapped);

        byte[] outcoming2 = new byte[]{(byte)0xAA,(byte)0xBB,(byte)0xCC};
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        Assert.assertArrayEquals(new byte[]{(byte)0xec,0x42,0x6d,(byte)0x9c,(byte)0xd3,0x27,0x6f,0x22,0x28,0x5a,(byte)0xb5,(byte)0xda,(byte)0x8d,(byte)0xf8,(byte)0xf2,0x6b,0x00,0x01,0x00,0x00,0x00,0x01}, outcoming2wrapped);

        byte[] incoming2 = new byte[]{};
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        Assert.assertArrayEquals(new byte[]{}, incoming2unwrapped);

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4)
     */
    @Test
    @Ignore("Integrity and privacy not implemented")
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthConfRc4() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"rc4\",algorithm=md5-sess".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = new byte[]{0x11,0x22,0x33,0x44};
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        Assert.assertArrayEquals(new byte[]{(byte)0x6a,(byte)0x93,(byte)0x28,(byte)0xca,(byte)0x63,(byte)0x4e,(byte)0x47,(byte)0xc8,(byte)0xd1,(byte)0xec,(byte)0xc3,(byte)0xc3,(byte)0xf6,(byte)0xe6,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00}, outcoming1wrapped);

        byte[] incoming1 = new byte[]{(byte)0x9f,(byte)0xc7,(byte)0xeb,(byte)0x1c,(byte)0x3c,(byte)0x9e,(byte)0x04,(byte)0xb5,(byte)0x2d,(byte)0xf6,(byte)0xe3,(byte)0x47,(byte)0xa3,(byte)0x89,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        Assert.assertArrayEquals(new byte[]{0x55,0x66,0x77,(byte)0x88}, incoming1unwrapped);

        byte[] outcoming2 = new byte[]{(byte)0xAA,(byte)0xBB,(byte)0xCC};
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        Assert.assertArrayEquals(new byte[]{(byte)0x7e,(byte)0x15,(byte)0xb9,(byte)0x40,(byte)0xfc,(byte)0xcb,(byte)0xb5,(byte)0x8a,(byte)0x56,(byte)0x12,(byte)0xf5,(byte)0x4d,(byte)0xa7,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01}, outcoming2wrapped);

        byte[] incoming2 = new byte[]{};
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        Assert.assertArrayEquals(new byte[]{}, incoming2unwrapped);

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=des)
     */
    @Test
    @Ignore("Integrity and privacy not implemented")
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthConfDes() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"des\",algorithm=md5-sess".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"des\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = new byte[]{0x11,0x22,0x33,0x44};
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        Assert.assertArrayEquals(new byte[]{(byte)0xb2,(byte)0xa1,(byte)0x2b,(byte)0xa8,(byte)0xcc,(byte)0xd1,(byte)0x03,(byte)0x0e,(byte)0x7d,(byte)0xa4,(byte)0xba,(byte)0xc5,(byte)0x7a,(byte)0x22,(byte)0x41,(byte)0x97,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00}, outcoming1wrapped);

        byte[] incoming1 = new byte[]{(byte)0x8b,(byte)0xc1,(byte)0x26,(byte)0x7e,(byte)0x71,(byte)0xa7,(byte)0x69,(byte)0x45,(byte)0x6f,(byte)0x0c,(byte)0x60,(byte)0xf0,(byte)0x30,(byte)0xe1,(byte)0x3f,(byte)0x32,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        Assert.assertArrayEquals(new byte[]{0x55,0x66,0x77,(byte)0x88}, incoming1unwrapped);

        byte[] outcoming2 = new byte[]{(byte)0xAA,(byte)0xBB,(byte)0xCC};
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        Assert.assertArrayEquals(new byte[]{(byte)0x13,(byte)0x14,(byte)0x4f,(byte)0xc9,(byte)0x0c,(byte)0xa6,(byte)0x5d,(byte)0x38,(byte)0x38,(byte)0xd3,(byte)0x54,(byte)0x7c,(byte)0xca,(byte)0x43,(byte)0xe8,(byte)0xad,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01}, outcoming2wrapped);

        byte[] incoming2 = new byte[]{};
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        Assert.assertArrayEquals(new byte[]{}, incoming2unwrapped);

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-56)
     */
    @Test
    @Ignore("Integrity and privacy not implemented")
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthConfRc456() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"rc4-56\",algorithm=md5-sess".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4-56\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = new byte[]{0x11,0x22,0x33,0x44};
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        Assert.assertArrayEquals(new byte[]{(byte)0x7a,(byte)0x77,(byte)0xc4,(byte)0xb8,(byte)0xb2,(byte)0x02,(byte)0x08,(byte)0xe5,(byte)0x02,(byte)0xe5,(byte)0xdc,(byte)0x09,(byte)0xbb,(byte)0xfc,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00}, outcoming1wrapped);

        byte[] incoming1 = new byte[]{(byte)0xc1,(byte)0x0a,(byte)0xcb,(byte)0xf7,(byte)0x37,(byte)0xcd,(byte)0xeb,(byte)0xf2,(byte)0x29,(byte)0x8d,(byte)0xf5,(byte)0x34,(byte)0x17,(byte)0xbc,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        Assert.assertArrayEquals(new byte[]{0x55,0x66,0x77,(byte)0x88}, incoming1unwrapped);

        byte[] outcoming2 = new byte[]{(byte)0xAA,(byte)0xBB,(byte)0xCC};
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        Assert.assertArrayEquals(new byte[]{(byte)0xef,(byte)0xcb,(byte)0x86,(byte)0x62,(byte)0x92,(byte)0x54,(byte)0x27,(byte)0x78,(byte)0x8b,(byte)0x0f,(byte)0xfe,(byte)0xab,(byte)0x2c,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01}, outcoming2wrapped);

        byte[] incoming2 = new byte[]{};
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        Assert.assertArrayEquals(new byte[]{}, incoming2unwrapped);

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=rc4-40)
     */
    @Test
    @Ignore("Integrity and privacy not implemented")
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthConfRc440() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"rc4-40\",algorithm=md5-sess".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"rc4-40\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

        byte[] outcoming1 = new byte[]{0x11,0x22,0x33,0x44};
        byte[] outcoming1wrapped = client.wrap(outcoming1, 0, outcoming1.length);
        Assert.assertArrayEquals(new byte[]{(byte)0xed,(byte)0x46,(byte)0xc6,(byte)0xb0,(byte)0xd3,(byte)0x8a,(byte)0xcb,(byte)0x71,(byte)0x9a,(byte)0xad,(byte)0x66,(byte)0x1f,(byte)0x96,(byte)0x25,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00}, outcoming1wrapped);

        byte[] incoming1 = new byte[]{(byte)0x44,(byte)0xac,(byte)0xa6,(byte)0x14,(byte)0x5a,(byte)0x89,(byte)0x35,(byte)0x3d,(byte)0x26,(byte)0x25,(byte)0x8e,(byte)0x52,(byte)0x47,(byte)0x24,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
        byte[] incoming1unwrapped = client.unwrap(incoming1, 0, incoming1.length);
        Assert.assertArrayEquals(new byte[]{0x55,0x66,0x77,(byte)0x88}, incoming1unwrapped);

        byte[] outcoming2 = new byte[]{(byte)0xAA,(byte)0xBB,(byte)0xCC};
        byte[] outcoming2wrapped = client.wrap(outcoming2, 0, outcoming2.length);
        Assert.assertArrayEquals(new byte[]{(byte)0xb7,(byte)0xbd,(byte)0xc8,(byte)0xf0,(byte)0x87,(byte)0x33,(byte)0x18,(byte)0x21,(byte)0x54,(byte)0x28,(byte)0x9e,(byte)0x7f,(byte)0x3d,(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01}, outcoming2wrapped);

        byte[] incoming2 = new byte[]{};
        byte[] incoming2unwrapped = client.unwrap(incoming2, 0, incoming2.length);
        Assert.assertArrayEquals(new byte[]{}, incoming2unwrapped);

    }


    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf, cipher=unknown)
     */
    @Test
    @Ignore("Integrity and privacy not implemented")
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthConfUnknown() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"unknown\",algorithm=md5-sess".getBytes();
        try{
            client.evaluateChallenge(message1);
            fail("Not throwed SaslException!");
        } catch (SaslException e) {}
        assertFalse(client.isComplete());

    }


    /**
     * More realms from server (realm="other-realm",realm="elwood.innosoft.com",realm="next-realm" -> elwood.innosoft.com)
     */
    @Test
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA6MHXh6VqTrRk\".getBytes();")
    public void testMoreRealmsFromServer() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray(), "elwood.innosoft.com");
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"other-realm\",realm=\"elwood.innosoft.com\",realm=\"next-realm\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=d388dad90d4bbd760a152321f2143af7,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=ea40f60335c427b5527b84dbabcdfffd".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }


    /**
     * No realms from server
     */
    @Test
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA6MHXh6VqTrRk\".getBytes();")
    public void testNoRealmsFromServer() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=695dcc815019923b9d438fd28c641aa9,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=ef0a550cd88d926ff426790bef156af3".getBytes();
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

        byte[] message1 = "qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
        try{
            client.evaluateChallenge(message1);
            fail("Not throwed SaslException!");
        } catch (SaslException e) {}
        assertFalse(client.isComplete());

    }


    /**
     * Blank nonce from server (connection with naughty server)
     */
    @Test
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"OA6MHXh6VqTrRk\".getBytes();")
    public void testBlankServerNonce() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "nonce=\"\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",nonce=\"\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=c87a63a455fed82d007a7996d49a51bc,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=fa4e5be53f9b154858fb82d96c93a03a".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }

    /**
     * Test successful authentication with Unicode chars (UTF-8 encoding)
     */
    @Test
    @BMRule(name = "Static nonce",
            targetClass = NONCE_CLASS,
            targetMethod = "generateNonce",
            action = "return \"cn\u0438\u4F60\uD83C\uDCA1\".getBytes();")
    public void testUtf8Charset() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("\u0438\u4F60\uD83C\uDCA1", "\u0438\u4F60\uD83C\uDCA1".toCharArray());
        client = Sasl.createSaslClient(new String[] { DIGEST }, null, "\u0438\u4F60\uD83C\uDCA1", "realm.\u0438\u4F60\uD83C\uDCA1.com", Collections.<String, Object> emptyMap(), clientCallback);
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"realm.\u0438\u4F60\uD83C\uDCA1.com\",nonce=\"sn\u0438\u4F60\uD83C\uDCA1\",charset=utf-8,algorithm=md5-sess".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"\u0438\u4F60\uD83C\uDCA1\",realm=\"realm.\u0438\u4F60\uD83C\uDCA1.com\",nonce=\"sn\u0438\u4F60\uD83C\uDCA1\",nc=00000001,cnonce=\"cn\u0438\u4F60\uD83C\uDCA1\",digest-uri=\"\u0438\u4F60\uD83C\uDCA1/realm.\u0438\u4F60\uD83C\uDCA1.com\",maxbuf=65536,response=420939e06d2d748c157c5e33499b41a9,qop=auth", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=9c4d137545617ba98c11aaea939b4381".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }

}