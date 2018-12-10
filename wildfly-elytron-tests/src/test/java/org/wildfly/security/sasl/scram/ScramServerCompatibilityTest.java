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
import java.security.NoSuchAlgorithmException;
import java.security.Permissions;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.permission.RunAsPrincipalPermission;
import org.wildfly.security.mechanism.scram.ScramClient;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.SaslServerBuilder;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

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

    private void mockNonce(final String nonce) {
        Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.mechanism.scram.ScramUtil", true, ScramClient.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock) {
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
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final PasswordFactory passwordFactory = PasswordFactory.getInstance(ScramDigestPassword.ALGORITHM_SCRAM_SHA_1);
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                .setUserName("user")
                .setPassword(password)
                .build();

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

        //        c="n,,"
        message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", new String(message, StandardCharsets.UTF_8));

        assertTrue(saslServer.isComplete());
        assertEquals("user", saslServer.getAuthorizationID());
    }

    private static Password getPassword(final String password, final String saltString) throws InvalidKeySpecException, NoSuchAlgorithmException {
        final PasswordFactory passwordFactory = PasswordFactory.getInstance(ScramDigestPassword.ALGORITHM_SCRAM_SHA_1);
        return passwordFactory.generatePassword(new EncryptablePasswordSpec(password.toCharArray(), new IteratedSaltedPasswordAlgorithmSpec(
            4096,
            CodePointIterator.ofString(saltString).base64Decode().drain()
        )));
    }

    /**
     * Test rejection of bad username
     */
    @Test
    public void testBadUsername() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("baduser")
                        .setPassword(password)
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
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pen", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword(password)
                        .build();

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

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
        mockNonce("3rfcNHYJY1ZVvWVs7j");

        final Map<String, Password> passwordMap = new HashMap<>();

        passwordMap.put("admin", getPassword("pencil", "QSXCR+Q6sek8bf92"));
        passwordMap.put("user", getPassword("pen", "QSXCR+Q6sek8bf92"));

        Permissions permissions = new Permissions();
        permissions.add(new RunAsPrincipalPermission("user"));

        SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setPasswordInstanceMap(passwordMap)
                        .setProtocol("acap").setServerName("elwood.innosoft.com")
                        .setPermissionsMap(Collections.singletonMap("admin", permissions))
                        .build();

        byte[] message = "n,a=user,n=admin,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

        //         c="n,a=user,"
        message = "c=bixhPXVzZXIs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=sSem09WkghLJOV/Ma5LjIqUtoo8=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=xzTfS758LckdRoQKN/ZFY/Bauxo=", new String(message, StandardCharsets.UTF_8));

        assertTrue(saslServer.isComplete());
        assertEquals(saslServer.getAuthorizationID(), "user");
    }

    /**
     * Test rejection of unauthorized authorization id
     */
    @Test
    public void testUnallowedAuthorizationId() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("admin")
                        .setPassword(password)
                        .setProtocol("acap").setServerName("elwood.innosoft.com")
                        .build();

        byte[] message = "n,a=user,n=admin,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

        //         c="n,a=user,"
        message = "c=bixhPXVzZXIs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=sSem09WkghLJOV/Ma5LjIqUtoo8=".getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not thrown");
        } catch (SaslException e) {
        }
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test rejection of different authorization id in FIRST and FINAL message
     */
    @Test
    public void testMismatchedAuthorizationId() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword(password)
                        .build();

        byte[] message = "n,a=user,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

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
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword(password)
                        .build();

        byte[] message = "n,a=user,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

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
        mockNonce("differentNonceVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword(password)
                        .build();

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawLdifferentNonceVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

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
        mockNonce("3rfcNHYJY1ZVvWVs7j");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        final Map<String, Password> passwordMap = new HashMap<>();
        passwordMap.put("strange=admin, \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301", getPassword("\"strange=admin=password, \\\\\\u0438\\u4F60\\uD83C\\uDCA1\\u00BD\\u00B4\"", "QSXCR+Q6sek8bf92"));
        passwordMap.put("strange=user, \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301", getPassword("strange=password, \\\u0438\u4F60\uD83C\uDCA1\u00BD\u00B4", "QSXCR+Q6sek8bf92"));

        Permissions permissions = new Permissions();
        permissions.add(new RunAsPrincipalPermission("strange=admin, \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301"));

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setProtocol("protocol")
                        .setPasswordInstanceMap(passwordMap)
                        .setPermissionsMap(Collections.singletonMap("strange=user, \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301", permissions))
                        .build();

        byte[] message = "n,a=strange=3Dadmin=2C \\\u0438\u4F60\uD83C\uDCA1\u0031\u2044\u0032\u0020\u0301,n=strange=3Duser=2C \\\u0438\u4F60\uD83C\uDCA1\u00BD\u00B4,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

        message = "c=bixhPXN0cmFuZ2U9M0RhZG1pbj0yQyBc0LjkvaDwn4KhMeKBhDIgzIEs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=ZWpaDThPD7OErOz+6Q+n9msNhMQ=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=k1gWxds6QP4FdDqmsLtaxIl38NM=", new String(message, StandardCharsets.UTF_8));
        assertTrue(saslServer.isComplete());
    }

    /**
     * Client does support channel binding and know the server does not and binding type or data is not sent
     */
    @Test
    public void testBindingCorrectY() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword(password)
                        .build();
        byte[] message = "y,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

        //        c="y,,"
        message = "c=eSws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=BjZF5dV+EkD3YCb3pH3IP8riMGw=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=dsprQ5R2AGYt1kn4bQRwTAE0PTU=", new String(message, StandardCharsets.UTF_8));
        assertTrue(saslServer.isComplete());
    }

    /**
     * Client does support channel binding, believes the server does not, but it does
     */
    @Test
    public void testBindingIncorrectYWithServerChannelBinding() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword(password)
                        .setChannelBinding("same-type", new byte[]{(byte) 0x00, (byte) 0x2C, (byte) 0xFF})
                        .build();
        byte[] message = "y,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("e=server-does-support-channel-binding", new String(message, StandardCharsets.UTF_8));
        assertFalse(saslServer.isComplete());
    }

    /**
     * Client does not support channel binding, and the server does support
     */
    @Test
    public void testBindingIncorrectNWithChannelBinding() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1)
                        .setUserName("user")
                        .setPassword(password)
                        .setChannelBinding("same-type", new byte[]{(byte) 0x00, (byte) 0x2C, (byte) 0xFF})
                        .build();
        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("e=server-does-support-channel-binding", new String(message, StandardCharsets.UTF_8));
        assertFalse(saslServer.isComplete());
    }

    /**
     * Client does support channel binding but thinks the server does not
     */
    @Test
    public void testBindingIncorrectY() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        Map<String, Object> props = new HashMap<>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, "true");
        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS)
                        .setUserName("user")
                        .setPassword(password)
                        .setChannelBinding("sameType", new byte[]{0x12,',', 0x00})
                        .setProperties(props)
                        .build();


        byte[] message = "y,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        assertEquals("e=server-does-support-channel-binding", new String(saslServer.evaluateResponse(message), StandardCharsets.UTF_8));
        assertFalse(saslServer.isComplete());
    }

    /**
     * Test authentication with correct requirement of channel binding (p=)
     */
    @Test
    public void testBindingCorrect() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        Map<String, Object> props = new HashMap<>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, "true");
        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS)
                        .setUserName("user")
                        .setPassword(password)
                        .setChannelBinding("same-type", new byte[]{(byte) 0x00, (byte) 0x2C, (byte) 0xFF})
                        .setProperties(props)
                        .build();


        byte[] message = "p=same-type,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

        //         c="p=same-type,\00\2C\FF"
        message = "c=cD1zYW1lLXR5cGUsLAAs/w==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=H8mpU86Osa2lDJvFElvu7qys7LE=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=/ubKPpiyDhhCsgGfHqY5Xm7msjM=", new String(message, StandardCharsets.UTF_8));
        assertTrue(saslServer.isComplete());
    }

    /**
     * Test authentication with channel binding with wrong binding data
     */
    @Test
    public void testBindingBadData() throws Exception {
        mockNonce("3rfcNHYJY1ZVvWVs7j");
        final Password password = getPassword("pencil", "QSXCR+Q6sek8bf92");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        Map<String, Object> props = new HashMap<>();
        props.put(WildFlySasl.CHANNEL_BINDING_REQUIRED, "true");
        final SaslServer saslServer =
                new SaslServerBuilder(ScramSaslServerFactory.class, SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS)
                        .setUserName("user")
                        .setPassword(password)
                        .setChannelBinding("same-type", new byte[]{(byte)0x99,(byte)0x99})
                        .setProperties(props)
                        .build();


        byte[] message = "p=same-type,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message, StandardCharsets.UTF_8));

        //         c="p=same-type,\00\2C\FF"
        message = "c=cD1zYW1lLXR5cGUsLAAs/w==,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=H8mpU86Osa2lDJvFElvu7qys7LE=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("e=channel-bindings-dont-match", new String(message, StandardCharsets.UTF_8));
        assertFalse(saslServer.isComplete());
    }
}
