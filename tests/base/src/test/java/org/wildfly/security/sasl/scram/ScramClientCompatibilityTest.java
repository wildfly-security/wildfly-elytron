/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.sasl.scram;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.sasl.scram.ScramCallbackHandlerUtils.createClientCallbackHandler;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.mechanism.scram.ScramClient;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.ChannelBindingSaslClientFactory;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * Test of client side of SCRAM mechanism.
 * JMockit ensure same generated nonce in every test run.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class ScramClientCompatibilityTest extends BaseTestCase {

    private static final Provider provider = WildFlyElytronSaslScramProvider.getInstance();

    @BeforeClass
    public static void registerPasswordProvider() {
        Security.insertProviderAt(provider, 1);
    }

    @AfterClass
    public static void removePasswordProvider() {
        Security.removeProvider(provider.getName());
    }

    private void mockNonce(final String nonce){
        final Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.mechanism.scram.ScramUtil", true, ScramClient.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock){
            @Mock
            public byte[] generateNonce(int length, Random random){
                return nonce.getBytes(StandardCharsets.UTF_8);
            }
        };
    }

    /**
     * Test communication by example in RFC 5802
     */
    @Test
    public void testRfc5802example() throws Exception {
        mockNonce("fyko+d2lbbFgONRv9qkxdawL");

        final SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);

        CallbackHandler cbh = createClientCallbackHandler("user", "pencil".toCharArray());
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.SCRAM_SHA_1 }, null, "protocol", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", new String(message, StandardCharsets.UTF_8));

        message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);
        assertEquals("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", new String(message, StandardCharsets.UTF_8));

        message = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);

        assertTrue(saslClient.isComplete());
    }

    /**
     * Test sending authorization id by client
     */
    @Test
    public void testAuthorizationId() throws Exception {
        mockNonce("fyko+d2lbbFgONRv9qkxdawL");

        final SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);

        CallbackHandler cbh = createClientCallbackHandler("admin", "secret".toCharArray());
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.SCRAM_SHA_1 }, "user", "protocol", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("n,a=user,n=admin,r=fyko+d2lbbFgONRv9qkxdawL", new String(message, StandardCharsets.UTF_8));

        message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);
        assertEquals("c=bixhPXVzZXIs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=JFcfWujky5ZULVQwDmB5aHMkoME=", new String(message, StandardCharsets.UTF_8));

        message = "v=EFUP6P+SBB3T4rZgjRz28Z1FqCg=".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);

        assertTrue(saslClient.isComplete());
    }

    /**
     * Test rejecting bad server nonce (not based on client nonce)
     */
    @Test
    public void testBadNonce() throws Exception {
        mockNonce("fyko+d2lbbFgONRv9qkxdawL");

        final SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);

        CallbackHandler cbh = createClientCallbackHandler("admin", "secret".toCharArray());
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.SCRAM_SHA_1 }, "user", "protocol", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("n,a=user,n=admin,r=fyko+d2lbbFgONRv9qkxdawL", new String(message, StandardCharsets.UTF_8));

        message = "r=BADo+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        try{
            message = saslClient.evaluateChallenge(message);
            fail("SaslException not throwed");
        } catch (SaslException e) {
        }
        assertFalse(saslClient.isComplete());
    }

    /**
     * Test rejecting bad verifier
     */
    @Test
    public void testBadVerifier() throws Exception {
        mockNonce("fyko+d2lbbFgONRv9qkxdawL");

        final SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);

        CallbackHandler cbh = createClientCallbackHandler("admin", "secret".toCharArray());
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.SCRAM_SHA_1 }, "user", "protocol", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("n,a=user,n=admin,r=fyko+d2lbbFgONRv9qkxdawL", new String(message, StandardCharsets.UTF_8));

        message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);
        assertEquals("c=bixhPXVzZXIs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=JFcfWujky5ZULVQwDmB5aHMkoME=", new String(message, StandardCharsets.UTF_8));

        message = "v=badP6P+SBB3T4rZgjRz28Z1FqCg=".getBytes(StandardCharsets.UTF_8);
        try{
            message = saslClient.evaluateChallenge(message);
            fail("SaslException not throwed");
        } catch (SaslException e) {
        }
        assertFalse(saslClient.isComplete());
    }

    /**
     * Test authentication with unusual characters in credentials (quoting of ',' and '=' + normalization)
     */
    @Test
    public void testStrangeCredentials() throws Exception {
        mockNonce("fyko+d2lbbFgONRv9qkxdawL");

        final SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);

        CallbackHandler cbh = createClientCallbackHandler("strange=user, \\\u0438\u4F60\uD83C\uDCA1\u00BD\u00B4", "strange=password, \\\u0438\u4F60\uD83C\uDCA1\u00BD\u00B4".toCharArray());
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.SCRAM_SHA_1 }, "strange=admin, \\\u0438\u4F60\uD83C\uDCA1\u00BD\u00B4", "protocol", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("n,a=strange=3Dadmin=2C \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301,n=strange=3Duser=2C \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301,r=fyko+d2lbbFgONRv9qkxdawL", new String(message, StandardCharsets.UTF_8));

        message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);
        assertEquals("c=bixhPXN0cmFuZ2U9M0RhZG1pbj0yQyBc0LjkvaDwn4KhMeKBhDIgzIEs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=5Drqrw2srEQfQ84h8Okz6eV091w=", new String(message, StandardCharsets.UTF_8));

        message = "v=7xo0Rb9jQts952duIEz4oaIfD/c=".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);

        assertTrue(saslClient.isComplete());
    }

    /**
     * Client does support channel binding and thinks the server does not
     */
    @Test
    public void testBindingCorrectY() throws Exception {
        mockNonce("fyko+d2lbbFgONRv9qkxdawL");

        CallbackHandler cbh = createClientCallbackHandler("user", "pencil".toCharArray());
        SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);
        clientFactory = new ChannelBindingSaslClientFactory(clientFactory, "same-type", new byte[]{0x12,',',0x00});
        assertNotNull(clientFactory);
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.SCRAM_SHA_1 }, null, "protocol", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("y,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", new String(message, StandardCharsets.UTF_8));

        message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);
        assertEquals("c=eSws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=BjZF5dV+EkD3YCb3pH3IP8riMGw=", new String(message, StandardCharsets.UTF_8));

        message = "v=dsprQ5R2AGYt1kn4bQRwTAE0PTU=".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);

        assertTrue(saslClient.isComplete());
    }

    /**
     * Client does support channel binding and server too
     */
    @Test
    public void testBindingCorrectP() throws Exception {
        mockNonce("fyko+d2lbbFgONRv9qkxdawL");


        CallbackHandler cbh = createClientCallbackHandler("user", "pencil".toCharArray());
        SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);
        clientFactory = new ChannelBindingSaslClientFactory(clientFactory, "same-type", new byte[]{0x12,',',0x00});
        assertNotNull(clientFactory);
        Map<String, String> props = new HashMap<String, String>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, "true");
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS }, null, "protocol", "localhost", props, cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("p=same-type,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", new String(message, StandardCharsets.UTF_8));

        message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);
        assertEquals("c=cD1zYW1lLXR5cGUsLBIsAA==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=0xrnDt+5S5sPyZE7IiTMKHbuZGQ=", new String(message, StandardCharsets.UTF_8));

        message = "v=ooHARfuURZosAZ4dAMTwrFBGBFc=".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);

        assertTrue(saslClient.isComplete());
    }

    /**
     * Test receiving server-error
     */
    @Test
    public void testServerError() throws Exception {
        mockNonce("fyko+d2lbbFgONRv9qkxdawL");

        final SaslClientFactory clientFactory = obtainSaslClientFactory(ScramSaslClientFactory.class);
        assertNotNull(clientFactory);

        CallbackHandler cbh = createClientCallbackHandler("admin", "secret".toCharArray());
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { SaslMechanismInformation.Names.SCRAM_SHA_1 }, "user", "protocol", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("n,a=user,n=admin,r=fyko+d2lbbFgONRv9qkxdawL", new String(message, StandardCharsets.UTF_8));

        message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);
        assertEquals("c=bixhPXVzZXIs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=JFcfWujky5ZULVQwDmB5aHMkoME=", new String(message, StandardCharsets.UTF_8));

        message = "e=invalid-proof".getBytes(StandardCharsets.UTF_8);
        try{
            message = saslClient.evaluateChallenge(message);
            fail("SaslException not thrown");
        } catch (SaslException e) {
            if(! e.getMessage().contains("invalid-proof")) fail("SaslException not contain error message (" + e.getMessage() + ")");
        }
        assertFalse(saslClient.isComplete());
    }

}
