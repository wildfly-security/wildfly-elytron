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

package org.wildfly.security.sasl.gssapi;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import mockit.Invocation;
import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.wildfly.security.ExcludedOnIbmJdk;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/*
 * Every GSSAPI compatibility test must be in standalone test class because Random instances
 * must be created for every test run new to ensure stable assertable output.
 */
@RunWith(JMockit.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category(ExcludedOnIbmJdk.class)
public class GssapiCompatibilitySuiteChild {

    protected boolean wildfly = true; // whether use WildFly or JDK SASL provider, set to false to obtain/verify reference output
    protected static final String TEST_SERVER_1 = "test_server_1";

    protected static SaslServer server;
    protected static SaslClient client;
    protected static Subject clientSubject;
    protected static Subject serverSubject;
    protected byte[] exchange;
    protected byte[] message;
    protected byte[] wrappedMessage;
    protected byte[] badMessage;

    private static final Provider wildFlyElytronProvider = new WildFlyElytronProvider();

    @Test
    public void test1Auth() throws Exception {

        client = Subject.doAs(clientSubject, (PrivilegedExceptionAction<SaslClient>) () -> {
            SaslClientFactory factory = findSaslClientFactory(wildfly);
            Map<String, String> props = new HashMap<>();
            props.put(Sasl.QOP, "auth");
            props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
            props.put(Sasl.MAX_BUFFER, Integer.toString(0));
            return factory.createSaslClient(new String[]{"GSSAPI"}, null, "sasl", TEST_SERVER_1, props, new NoCallbackHandler());
        });

        server = Subject.doAs(serverSubject, (PrivilegedExceptionAction<SaslServer>) () -> {
            SaslServerFactory factory = findSaslServerFactory(wildfly);
            Map<String, String> props = new HashMap<>();
            props.put(Sasl.QOP, "auth");
            props.put(Sasl.MAX_BUFFER, Integer.toString(0));
            return factory.createSaslServer("GSSAPI", "sasl", TEST_SERVER_1, props, new AuthorizeOnlyCallbackHandler());
        });

        assertTrue(client.hasInitialResponse());

        exchange = new byte[0];
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("6082020406092a864886f71201020201006e8201f3308201efa003020105a10302010ea20703050020000000a382010b6182010730820103a003020105a10d1b0b57494c44464c592e4f5247a220301ea003020100a11730151b047361736c1b0d746573745f7365727665725f31a381ca3081c7a003020110a281bf0481bcc63454190127bdcbe1a3e8882997054846e9b33a71bc3502a187047bfae5fb7a51c2b4f7a8421d9a57c4a1d213d9a53a84e1ccafb0bd815fa0bd24ccf8339045b92eb290b5e68aea93647344c0a8e9a19293db22a886531f93f91f6e2acdde2d20cbe55e6e99585a95d78ef2806ba760a790e3c850b2056e3ba697165aac7be8341da6f445f80483676562fe3ac4010dc970bbd2b805883353671e345d019fd558e5e48250d38d77816ff3cf72803af69a59c7d3baef13ee873a705aa481ca3081c7a003020110a281bf0481bc0629dff17e931bfdc13423dc521b92255bd527310726085b18d917c003ed6de73f640fd602b7b43a30709199dd89f55a12cc44d2669d5cd4d150fa94f785d57ae3eadbc58ff65970e0c118243f372fc4fd7ed2c57b2d4ccd3b2149fedbfd8f1fdf67d6e161884550dfaa8f4db3bfcdee174d3d418e829b4a8113977f4fabe330ec4dc19ebfae3235a968a364e5f8dd5d908a5634cf50c38c8d9a5b03acb794d3d1f1337e360c0de4f0510f255956eba6b892817bf9a7c9d4665ede66", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("606c06092a864886f71201020202006f5d305ba003020105a10302010fa24f304da003020110a246044462c52b3dbeb16479835a16dfa53b7897c8ac59f11f1bb86cd2bb815f6943c8566af985a5a375f0fa1b6765086091f584cf9186ef88ab6d1f46c3a55cc2c481a2d82d9df8", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffffae63d6c0c7d61b6ff9054237068ce2f1794d7c77bbec42f6623fe19798041b045be796b80100000004040404", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffffb935da04f99c7978182e9fd1c088aa3366dfc60faf04fa2e09ffa0597f53358278f26cb80100000004040404", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());
        assertTrue(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals(null, exchange);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("jduke@WILDFLY.ORG", server.getAuthorizationID());
        assertEquals("auth", server.getNegotiatedProperty(Sasl.QOP));
        assertEquals("auth", client.getNegotiatedProperty(Sasl.QOP));
    }

    @Test
    public void test2AuthInt() throws Exception {

        client = Subject.doAs(clientSubject, (PrivilegedExceptionAction<SaslClient>) () -> {
            SaslClientFactory factory = findSaslClientFactory(wildfly);
            Map<String, String> props = new HashMap<>();
            props.put(Sasl.QOP, "auth-int");
            props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
            props.put(Sasl.MAX_BUFFER, Integer.toString(61234));
            return factory.createSaslClient(new String[]{"GSSAPI"}, null, "sasl", TEST_SERVER_1, props, new NoCallbackHandler());
        });

        server = Subject.doAs(serverSubject, (PrivilegedExceptionAction<SaslServer>) () -> {
            SaslServerFactory factory = findSaslServerFactory(wildfly);
            Map<String, String> props = new HashMap<>();
            props.put(Sasl.QOP, "auth-int");
            props.put(Sasl.MAX_BUFFER, Integer.toString(64321));
            return factory.createSaslServer("GSSAPI", "sasl", TEST_SERVER_1, props, new AuthorizeOnlyCallbackHandler());
        });

        assertTrue(client.hasInitialResponse());

        exchange = new byte[0];
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("6082020406092a864886f71201020201006e8201f3308201efa003020105a10302010ea20703050020000000a382010b6182010730820103a003020105a10d1b0b57494c44464c592e4f5247a220301ea003020100a11730151b047361736c1b0d746573745f7365727665725f31a381ca3081c7a003020110a281bf0481bcc63454190127bdcbe1a3e8882997054846e9b33a71bc3502a187047bfae5fb7a51c2b4f7a8421d9a57c4a1d213d9a53a84e1ccafb0bd815fa0bd24ccf8339045b92eb290b5e68aea93647344c0a8e9a19293db22a886531f93f91f6e2acdde2d20cbe55e6e99585a95d78ef2806ba760a790e3c850b2056e3ba697165aac7be8341da6f445f80483676562fe3ac4010dc970bbd2b805883353671e345d019fd558e5e48250d38d77816ff3cf72803af69a59c7d3baef13ee873a705aa481ca3081c7a003020110a281bf0481bc9200340be1125d0d3fb9a5be26c334ab61e90eb38e7e10f2141617c5df0236e39b44dbb3f728e0ce33ebe9c7d69803987f73d01d5d7ebd47ce7770c624c7b875a6d2e461b0eea72f2eadc877353d2ac3354a6c4abe9f1f3400661511233a4670b15d13c9ffd024b4f7dd8036dc5f1d8affce237f19cd811e74ef24d2aa2d19f555f40a6994ee2ad3bca327f1c936abb99e2e35f835a32658361c71b6c6396b3890ae4a6e5eb7c92928c84e03081609f248a3ecc7cadb90f82c710173", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("606c06092a864886f71201020202006f5d305ba003020105a10302010fa24f304da003020110a246044403ac37fbdbaee958627c0cdba251b00b1a5c62cbf27283a887e4e2eee0d2c3d0fad61d97fc67382906067f14cc81ce51e6366d5ffac2cfa01633e381f2521898b6a77a0d", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffffe01f094eec97ca846769c86c71ffe6c1bbc46628965de82b1d8eb4dd30553fd61f3cd7770200fb4104040404", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffff97e47865e8d01b16f61a0fccd5c373659ef1d6a36cd6d40e4e8457c979438dad0319e89d0200ef3204040404", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertTrue(client.isComplete());
        assertEquals("auth-int", client.getNegotiatedProperty(Sasl.QOP));
        assertEquals("61234", client.getNegotiatedProperty(Sasl.MAX_BUFFER));
        assertEquals("64252", client.getNegotiatedProperty(Sasl.RAW_SEND_SIZE));

        exchange = evaluateByServer(exchange);
        assertEquals(null, exchange);
        assertTrue(server.isComplete());
        assertEquals("jduke@WILDFLY.ORG", server.getAuthorizationID());
        assertEquals("auth-int", server.getNegotiatedProperty(Sasl.QOP));
        assertEquals("64321", server.getNegotiatedProperty(Sasl.MAX_BUFFER));
        assertEquals("61165", server.getNegotiatedProperty(Sasl.RAW_SEND_SIZE));

        message = new byte[]{(byte)0x00,(byte)0x12,(byte)0x34,(byte)0x56,(byte)0x78,(byte)0x9A,(byte)0xBC,(byte)0xDE,(byte)0xFF};
        wrappedMessage = server.wrap(message, 0, message.length);
        assertEquals("604706092a864886f71201020202010400ffffffff1dd8349942ed1e68a888eacc887d80fef4afcb3fd8c167606ee19ca040baaa586e3731e100123456789abcdeff07070707070707", ByteIterator.ofBytes(wrappedMessage).hexEncode().drainToString());

        message = client.unwrap(wrappedMessage, 0, wrappedMessage.length);
        Assert.assertArrayEquals(message, new byte[]{(byte)0x00,(byte)0x12,(byte)0x34,(byte)0x56,(byte)0x78,(byte)0x9A,(byte)0xBC,(byte)0xDE,(byte)0xFF});

        message = new byte[]{(byte)0xFF,(byte)0xED,(byte)0xCB,(byte)0xA9,(byte)0x87,(byte)0x65,(byte)0x43,(byte)0x21,(byte)0x00};
        wrappedMessage = client.wrap(message, 0, message.length);
        assertEquals("604706092a864886f71201020202010400ffffffff3d33fb3f1b740c814444cce42c925927f97191b40cb9ac71809242074058c1edcb7c5858ffedcba9876543210007070707070707", ByteIterator.ofBytes(wrappedMessage).hexEncode().drainToString());

        message = server.unwrap(wrappedMessage, 0, wrappedMessage.length);
        Assert.assertArrayEquals(message, new byte[]{(byte)0xFF,(byte)0xED,(byte)0xCB,(byte)0xA9,(byte)0x87,(byte)0x65,(byte)0x43,(byte)0x21,(byte)0x00});

        try {
            badMessage = CodePointIterator.ofString("605706092a864886f712010202020104000200ffffe95b9a1821e8ed3d21b4abf3c62ca45e92638a381552f56e5ef247fac3b40bc614e465f25d2e30dd445266bbc5c648fcd2a124fc").hexDecode().drain();
            client.unwrap(badMessage, 0, badMessage.length);
            fail("SaslException on bad message into client not thrown!");
        } catch(SaslException e) {}

        try {
            badMessage = CodePointIterator.ofString("604706092a864886f712010202020904000200ffffea352a02de5169baaac0987aea3014538c86ff1023da61a2023677386011794e02afb3dd0bf2722d361e1eec5037ab9ba101f3ee").hexDecode().drain();
            server.unwrap(badMessage, 0, badMessage.length);
            fail("SaslException on bad message into server not thrown!");
        } catch(SaslException e) {}
    }

    @Test
    public void test3AuthConf() throws Exception {

        client = Subject.doAs(clientSubject, (PrivilegedExceptionAction<SaslClient>) () -> {
            SaslClientFactory factory = findSaslClientFactory(wildfly);
            Map<String, String> props = new HashMap<>();
            props.put(Sasl.QOP, "auth-conf");
            props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
            props.put(Sasl.MAX_BUFFER, Integer.toString(61234));
            return factory.createSaslClient(new String[]{"GSSAPI"}, null, "sasl", TEST_SERVER_1, props, new NoCallbackHandler());
        });

        server = Subject.doAs(serverSubject, (PrivilegedExceptionAction<SaslServer>) () -> {
            SaslServerFactory factory = findSaslServerFactory(wildfly);
            Map<String, String> props = new HashMap<>();
            props.put(Sasl.QOP, "auth-conf");
            props.put(Sasl.MAX_BUFFER, Integer.toString(64321));
            return factory.createSaslServer("GSSAPI", "sasl", TEST_SERVER_1, props, new AuthorizeOnlyCallbackHandler());
        });

        assertTrue(client.hasInitialResponse());

        exchange = new byte[0];
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("6082020406092a864886f71201020201006e8201f3308201efa003020105a10302010ea20703050020000000a382010b6182010730820103a003020105a10d1b0b57494c44464c592e4f5247a220301ea003020100a11730151b047361736c1b0d746573745f7365727665725f31a381ca3081c7a003020110a281bf0481bcc63454190127bdcbe1a3e8882997054846e9b33a71bc3502a187047bfae5fb7a51c2b4f7a8421d9a57c4a1d213d9a53a84e1ccafb0bd815fa0bd24ccf8339045b92eb290b5e68aea93647344c0a8e9a19293db22a886531f93f91f6e2acdde2d20cbe55e6e99585a95d78ef2806ba760a790e3c850b2056e3ba697165aac7be8341da6f445f80483676562fe3ac4010dc970bbd2b805883353671e345d019fd558e5e48250d38d77816ff3cf72803af69a59c7d3baef13ee873a705aa481ca3081c7a003020110a281bf0481bcc9e23417dcf0e217a2816ff35831f68b75db5fe72ed6b77b0df6479a1d9ea13fc58e9273b61ef5981a00a214b377f760e8759d8ad1f245bc6ba47169d7ba206a552ac8a7f1190b3f8abccde4f90a4328e0590d089627750d77daf006b6fa229f75a5188e0d55609cebd2bfb571b12d44bce825d142b2b89713d642da8a70d0b4cbb7a312fc58f20068f8d54461b655585d66e7bfeaddb0646f54f8e63e30e61472136751c0bebdd82174711c3cce7fcc4fd258903aa0ef75b180641e", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("606c06092a864886f71201020202006f5d305ba003020105a10302010fa24f304da003020110a2460444c78562b3adc482e49a1f52e2fcca10289a517ee45c01e611cdf1ee608dfcd66c3770418886b039f35195f27907a1bc1a4b914e585cde5ec554310e591ff9aaab398e3405", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffffc7b0c744711a14816e8344de68eccd98c2e82d9d61c27ba02f798bb6a193f404aed2bb080400fb4104040404", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertFalse(server.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffff371bed683be0dc53f69f877b367e4c39d99ec4b6505cda255735dca5261f317451cefc580400ef3204040404", ByteIterator.ofBytes(exchange).hexEncode().drainToString());
        assertTrue(client.isComplete());
        assertEquals("auth-conf", client.getNegotiatedProperty(Sasl.QOP));
        assertEquals("61234", client.getNegotiatedProperty(Sasl.MAX_BUFFER));
        assertEquals("64252", client.getNegotiatedProperty(Sasl.RAW_SEND_SIZE));

        exchange = evaluateByServer(exchange);
        assertEquals(null, exchange);
        assertTrue(server.isComplete());
        assertEquals("jduke@WILDFLY.ORG", server.getAuthorizationID());
        assertEquals("auth-conf", server.getNegotiatedProperty(Sasl.QOP));
        assertEquals("64321", server.getNegotiatedProperty(Sasl.MAX_BUFFER));
        assertEquals("61165", server.getNegotiatedProperty(Sasl.RAW_SEND_SIZE));

        message = new byte[]{(byte)0x00,(byte)0x12,(byte)0x34,(byte)0x56,(byte)0x78,(byte)0x9A,(byte)0xBC,(byte)0xDE,(byte)0xFF};
        wrappedMessage = server.wrap(message, 0, message.length);
        assertEquals("604706092a864886f712010202020104000200fffff543a21b273aa5a67730d46f1a35fcf852f2ac043226418d5232dc43afa08197bdec87fd82c7be886b588daff0bfeaeae3da9209", ByteIterator.ofBytes(wrappedMessage).hexEncode().drainToString());

        message = client.unwrap(wrappedMessage, 0, wrappedMessage.length);
        Assert.assertArrayEquals(message, new byte[]{(byte)0x00,(byte)0x12,(byte)0x34,(byte)0x56,(byte)0x78,(byte)0x9A,(byte)0xBC,(byte)0xDE,(byte)0xFF});

        message = new byte[]{(byte)0xFF,(byte)0xED,(byte)0xCB,(byte)0xA9,(byte)0x87,(byte)0x65,(byte)0x43,(byte)0x21,(byte)0x00};
        wrappedMessage = client.wrap(message, 0, message.length);
        assertEquals("604706092a864886f712010202020104000200ffff4e11e8a26ea77462f1b2742b3b1c748e9f5110f76052d5b0e1a830adc56db9ccc83ca8f598348f5255fa0130608a23f1156594ee", ByteIterator.ofBytes(wrappedMessage).hexEncode().drainToString());

        message = server.unwrap(wrappedMessage, 0, wrappedMessage.length);
        Assert.assertArrayEquals(message, new byte[]{(byte)0xFF,(byte)0xED,(byte)0xCB,(byte)0xA9,(byte)0x87,(byte)0x65,(byte)0x43,(byte)0x21,(byte)0x00});

        try {
            badMessage = CodePointIterator.ofString("605706092a864886f712010202020104000200ffffe95b9a1821e8ed3d21b4abf3c62ca45e92638a381552f56e5ef247fac3b40bc614e465f25d2e30dd445266bbc5c648fcd2a124fc").hexDecode().drain();
            client.unwrap(badMessage, 0, badMessage.length);
            fail("SaslException on bad message into client not thrown!");
        } catch(SaslException e) {}

        try {
            badMessage = CodePointIterator.ofString("604706092a864886f712010202020904000200ffffea352a02de5169baaac0987aea3014538c86ff1023da61a2023677386011794e02afb3dd0bf2722d361e1eec5037ab9ba101f3ee").hexDecode().drain();
            server.unwrap(badMessage, 0, badMessage.length);
            fail("SaslException on bad message into server not thrown!");
        } catch(SaslException e) {}

    }

    @BeforeClass
    public static void mock() {
        new MockUp<Random>() {
            @Mock
            public void $init(Invocation inv) throws Exception {
                Field field = Random.class.getDeclaredField("seed");
                field.setAccessible(true);
                field.set(inv.getInvokedInstance(), new AtomicLong(7326906125774241L));
            }
        };
        new MockUp<SecureRandom>() {
            Random random = new Random();
            @Mock
            public void nextBytes(byte[] bytes){
                random.nextBytes(bytes);
            }
        };
        new MockUp<System>() {
            @Mock
            public long currentTimeMillis(){
                return 123;
            }
            @Mock
            public long nanoTime(){
                return 1234;
            }
        };
    }

    @BeforeClass
    public static void registerProvider() {
        AccessController.doPrivileged((PrivilegedAction<Integer>) () -> {
            return Security.insertProviderAt(wildFlyElytronProvider, 1);
        });
    }

    @AfterClass
    public static void removeProvider() {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            Security.removeProvider(wildFlyElytronProvider.getName());
            return null;
        });
    }

    @BeforeClass
    public static void init() throws Exception {
        clientSubject = JaasUtil.loginClient();
        serverSubject = JaasUtil.loginServer(GssapiTestSuite.serverKeyTab, false);
    }

    protected byte[] evaluateByServer(final byte[] exchange) throws PrivilegedActionException {
        return Subject.doAs(serverSubject, (PrivilegedExceptionAction<byte[]>) () -> server.evaluateResponse(exchange));
    }

    protected byte[] evaluateByClient(final byte[] exchange) throws PrivilegedActionException {
        return Subject.doAs(clientSubject, (PrivilegedExceptionAction<byte[]>) () -> client.evaluateChallenge(exchange));
    }

    protected SaslClientFactory findSaslClientFactory(final boolean wildFlyProvider) throws Exception {
        Provider p = findProvider("SaslClientFactory.GSSAPI", wildFlyProvider);
        String factoryName = (String) p.get("SaslClientFactory.GSSAPI");
        return (SaslClientFactory) BaseGssapiTests.class.getClassLoader().loadClass(factoryName).newInstance();
    }

    protected SaslServerFactory findSaslServerFactory(final boolean wildFlyProvider) throws Exception {
        Provider p = findProvider("SaslServerFactory.GSSAPI", wildFlyProvider);
        String factoryName = (String) p.get("SaslServerFactory.GSSAPI");
        return (SaslServerFactory) BaseGssapiTests.class.getClassLoader().loadClass(factoryName).newInstance();
    }

    protected Provider findProvider(final String filter, final boolean wildFlyProvider) throws Exception {
        Provider[] providers = Security.getProviders(filter);
        for (Provider current : providers) {
            if (wildFlyProvider && current instanceof WildFlyElytronProvider) {
                return current;
            }
            if (!wildFlyProvider && !(current instanceof WildFlyElytronProvider)) {
                return current;
            }
        }
        throw new NoSuchProviderException("Provider not found (filter="+filter+",wildFly="+Boolean.toString(wildFlyProvider)+")");
    }

    protected class AuthorizeOnlyCallbackHandler implements CallbackHandler {
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback current : callbacks) {
                if (current instanceof AuthorizeCallback) {
                    AuthorizeCallback ac = (AuthorizeCallback) current;
                    ac.setAuthorized(ac.getAuthorizationID().equals(ac.getAuthenticationID()));
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }
        }
    }

    protected class NoCallbackHandler implements CallbackHandler {
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            throw new UnsupportedCallbackException(callbacks[0]);
        }
    }
}
