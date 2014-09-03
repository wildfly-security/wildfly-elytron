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

    protected static final String DIGEST = "DIGEST-MD5";
    protected static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
    protected static final String QOP_PROPERTY = "javax.security.sasl.qop";

    private SaslClient client;

    /**
     * Test communication by first example in RFC 2831 [page 18]
     */
    @Test
    @BMRule(name = "Static nonce",
            //targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
            targetClass = "org.wildfly.sasl.md5digest.AbstractMD5DigestMechanism",
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
        //byte[] message4 = client.evaluateChallenge(message3);
        //assertEquals(null, message4);
        //assertTrue(client.isComplete());

    }

    /**
     * Test communication by second example in RFC 2831 [page 18]
     */
    @Test
    @BMRule(name = "Static nonce",
            //targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
            targetClass = "org.wildfly.sasl.md5digest.AbstractMD5DigestMechanism",
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
        //byte[] message4 = client.evaluateChallenge(message3);
        //assertEquals(null, message4);
        //assertTrue(client.isComplete());

    }

    /**
     * Test with authorization ID (authzid) - authorized
     */
    @Test
    @BMRule(name = "Static nonce",
            //targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
            targetClass = "org.wildfly.sasl.md5digest.AbstractMD5DigestMechanism",
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
        //byte[] message4 = client.evaluateChallenge(message3);
        //assertEquals(null, message4);
        //assertTrue(client.isComplete());

    }

    /**
     * Test with authentication plus integrity protection (qop=auth-int)
     */
    @Test
    @BMRule(name = "Static nonce",
            //targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
            targetClass = "org.wildfly.sasl.md5digest.AbstractMD5DigestMechanism",
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
        //byte[] message4 = client.evaluateChallenge(message3);
        //assertEquals(null, message4);
        //assertTrue(client.isComplete());

    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf)
     */
    @Test
    @Ignore("Client cipher choosing not implemented yet")
    @BMRule(name = "Static nonce",
            //targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
            targetClass = "org.wildfly.sasl.md5digest.AbstractMD5DigestMechanism",
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

    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf,cipher=3des)
     */
    @Test
    @Ignore("Client cipher choosing not implemented yet")
    @BMRule(name = "Static nonce",
            //targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
            targetClass = "org.wildfly.sasl.md5digest.AbstractMD5DigestMechanism",
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthConf3des() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"3des\",algorithm=md5-sess".getBytes();
        byte[] message2 = client.evaluateChallenge(message1);
        assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=4520cf48234bb93b95548a25cd56601b,qop=auth-conf,cipher=\"3des\",authzid=\"chris\"", new String(message2, "UTF-8"));
        assertFalse(client.isComplete());

        byte[] message3 = "rspauth=a804fda66588e2d911bbacd1b1163bc1".getBytes();
        byte[] message4 = client.evaluateChallenge(message3);
        assertEquals(null, message4);
        assertTrue(client.isComplete());

    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf,cipher=des)
     */
    @Test
    @Ignore("Client cipher choosing not implemented yet")
    @BMRule(name = "Static nonce",
            //targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
            targetClass = "org.wildfly.sasl.md5digest.AbstractMD5DigestMechanism",
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

    }

    /**
     * Test with authentication plus integrity and confidentiality protection (qop=auth-conf,cipher=des)
     */
    @Test
    @Ignore("Client cipher choosing not implemented yet")
    @BMRule(name = "Static nonce",
            targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
            //targetClass = "org.wildfly.sasl.md5digest.AbstractMD5DigestMechanism",
            targetMethod = "generateNonce",
            action = "return \"OA9BSuZWMSpW8m\".getBytes();")
    public void testQopAuthConfUnknown() throws Exception {

        CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
        Map<String, Object> clientProps = new HashMap<String, Object>();
        clientProps.put(QOP_PROPERTY, "auth-conf");
        client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", clientProps, clientCallback);
        assertFalse(client.hasInitialResponse());
        assertFalse(client.isComplete());

        byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth-conf\",charset=utf-8,cipher=\"foo\",algorithm=md5-sess".getBytes();
        try{
            client.evaluateChallenge(message1);
            throw new Exception("Not throwed SaslException!");
        } catch (SaslException e) {}
        assertFalse(client.isComplete());
    }

}
