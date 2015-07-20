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

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.test.ServerCallbackHandler;
import org.wildfly.security.util.CodePointIterator;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

/**
 * Test of server side of SCRAM mechanism.
 * JMockit ensure same generated nonce in every test run.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class ScramServerCompatibilityTest extends BaseTestCase {

    private void mockNonceSalt(final String nonce, final String salt){
        new MockUp<ScramUtil>(){
            @Mock
            public byte[] generateNonce(int length, Random random){
                return nonce.getBytes(StandardCharsets.UTF_8);
            }
            @Mock
            public byte[] generateSalt(int length, Random random){
                return CodePointIterator.ofString(salt).hexDecode().drain();
            }
        };
    }

    /**
     * Test communication by example in RFC 5802
     */
    @Test
    public void testRfc5802example() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1)
                .setUserName("user")
                .setPassword("pencil".toCharArray())
                .build();

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //        c="n,,"
        message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", new String(message));

        assertTrue(saslServer.isComplete());
        assertEquals("user", saslServer.getAuthorizationID());
    }

    /**
     * Test rejection of bad username
     */
    @Test
    public void testBadUsername() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1)
                        .setUserName("baduser")
                        .setPassword("pencil".toCharArray())
                        .build();

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not thrown");
        } catch (SaslException e) {
        }
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test rejection of bad password
     */
    @Test
    public void testBadPassword() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword("pen".toCharArray())
                        .build();

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
                .getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not thrown");
        } catch (SaslException e) {
        }
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test allowing of authorized authorization id
     */
    @Test
    public void testAllowedAuthorizationId() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        //Use the test callback handler here since it does some extra validation of the authzid
        CallbackHandler cbh = new ServerCallbackHandler("admin", "clear", new ClearPasswordSpec("pencil".toCharArray()), "user");
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

        byte[] message = "n,a=user,n=admin,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //         c="n,a=user,"
        message = "c=bixhPXVzZXIs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=sSem09WkghLJOV/Ma5LjIqUtoo8=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=xzTfS758LckdRoQKN/ZFY/Bauxo=", new String(message));

        assertTrue(saslServer.isComplete());
        assertEquals(saslServer.getAuthorizationID(), "user");
    }

    /**
     * Test rejection of unauthorized authorization id
     */
    @Test
    public void testUnallowedAuthorizationId() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword("pencil".toCharArray())
                        .build();

        byte[] message = "n,a=admin,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        message = "c=bixhPWFkbWluLA==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=NdEpo1qMJaCn9xyrYplfuEKubqQ=".getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not thrown");
        } catch (SaslException e) {
            e.printStackTrace();
        }
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test rejection of different authorization id in FIRST and FINAL message
     */
    @Test
    public void testMismatchedAuthorizationId() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword("pencil".toCharArray())
                        .build();

        byte[] message = "n,a=user,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //         c="n,a=admin,"
        message = "c=bixhPWFkbWluLA==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=NdEpo1qMJaCn9xyrYplfuEKubqQ="
                .getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not throwed");
        } catch (SaslException e) {
        }
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test rejection of different authorization id in FIRST and FINAL message
     */
    @Test
    public void testMismatchedAuthorizationIdBlank() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword("pencil".toCharArray())
                        .build();

        byte[] message = "n,a=user,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //        c="n,,"
        message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
                .getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not throwed");
        } catch (SaslException e) {
        }
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test rejection of correct credentials and non-corresponding nonce
     */
    @Test
    public void testDifferentNonceAttack() throws Exception {
        mockNonceSalt("differentNonceVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword("pencil".toCharArray())
                        .build();

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawLdifferentNonceVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
                .getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not throwed");
        } catch (SaslException e) {
        }
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test authentication with unusual characters in credentials (quoting of ',' and '=')
     */
    @Test
    public void testStrangeCredentials() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j","4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        //Use the test callback handler here since it does some extra validation of the authzid
        CallbackHandler cbh = new ServerCallbackHandler("strange=user, \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301", "clear", new ClearPasswordSpec("strange=password, \\\u0438\u4F60\uD83C\uDCA1\u00BD\u00B4".toCharArray()), "strange=admin, \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301");
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "protocol", "server", Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

        byte[] message = "n,a=strange=3Dadmin=2C \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301,n=strange=3Duser=2C \\\u0438\u4F60\uD83C\uDCA1\u00BD\u00B4,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        message = "c=bixhPXN0cmFuZ2U9M0RhZG1pbj0yQyBc0LjkvaDwn4KhMeKBhDIgzIEs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=ZWpaDThPD7OErOz+6Q+n9msNhMQ=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=k1gWxds6QP4FdDqmsLtaxIl38NM=", new String(message));
        assertTrue(saslServer.isComplete());
    }

    /**
     * Client does support channel binding and know the server does not
     */
    @Test
    public void testBindingCorrectY() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword("pencil".toCharArray())
                        .build();

        byte[] message = "y,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //        c="y,,"
        message = "c=eSws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=BjZF5dV+EkD3YCb3pH3IP8riMGw=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=dsprQ5R2AGYt1kn4bQRwTAE0PTU=", new String(message));
        assertTrue(saslServer.isComplete());
    }


    /**
     * Client does support channel binding but thinks the server does not
     */
    @Test
    public void testBindingIncorrectY() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        Map<String, Object> props = new HashMap<>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, "true");
        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1_PLUS)
                        .setUserName("user")
                        .setPassword("pencil".toCharArray())
                        .setChannelBinding("sameType", new byte[]{0x12,',', 0x00})
                        .setProperties(props)
                        .build();


        byte[] message = "y,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not throwed");
        } catch (SaslException e) {
        }
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test authentication with correct requirement of channel binding (p=)
     */
    @Test
    public void testBindingCorrect() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        Map<String, Object> props = new HashMap<>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, "true");
        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1_PLUS)
                        .setUserName("user")
                        .setPassword("pencil".toCharArray())
                        .setChannelBinding("same-type", new byte[]{(byte) 0x00, (byte) 0x2C, (byte) 0xFF})
                        .setProperties(props)
                        .build();


        byte[] message = "p=same-type,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //         c="p=same-type,\00\2C\FF"
        message = "c=cD1zYW1lLXR5cGUsLAAs/w==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=H8mpU86Osa2lDJvFElvu7qys7LE=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=/ubKPpiyDhhCsgGfHqY5Xm7msjM=", new String(message));
        assertTrue(saslServer.isComplete());
    }

    /**
     * Test authentication with channel binding with wrong binding data
     */
    @Test
    public void testBindingBadData() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j","4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        Map<String, Object> props = new HashMap<>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, "true");
        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, Scram.SCRAM_SHA_1_PLUS)
                        .setUserName("user")
                        .setPassword("pencil".toCharArray())
                        .setChannelBinding("same-type", new byte[]{(byte)0x99,(byte)0x99})
                        .setProperties(props)
                        .build();


        byte[] message = "p=same-type,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //         c="p=same-type,\00\2C\FF"
        message = "c=cD1zYW1lLXR5cGUsLAAs/w==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=H8mpU86Osa2lDJvFElvu7qys7LE=".getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not throwed");
        } catch (SaslException e) {
        }
        assertFalse(saslServer.isComplete());
    }

    private SaslServerFactory getServerFactory() {
        return obtainSaslServerFactory(ScramSaslServerFactory.class);
    }
}
