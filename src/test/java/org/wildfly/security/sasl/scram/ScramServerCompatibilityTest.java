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

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Random;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.ServerCallbackHandler;
import org.wildfly.security.util.CodePointIterator;

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
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j","4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        CallbackHandler cbh = new ServerCallbackHandler("user", "clear", new ClearPasswordSpec("pencil".toCharArray()));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //        c="n,,"
        message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", new String(message));

        assertTrue(saslServer.isComplete());
    }

    /**
     * Test rejection of bad username
     */
    @Test
    public void testBadUsername() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");
        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);
        CallbackHandler cbh = new ServerCallbackHandler("baduser", "clear", new ClearPasswordSpec("pencil".toCharArray()));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost",
                Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        try {
            saslServer.evaluateResponse(message);
            fail("SaslException not throwed");
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

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        CallbackHandler cbh = new ServerCallbackHandler("user", "clear", new ClearPasswordSpec("pen".toCharArray()));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost",
                Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

        byte[] message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

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
     * Test allowing of authorized authorization id
     */
    @Test
    public void testAllowedAuthorizationId() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        CallbackHandler cbh = new ServerCallbackHandler("user", "clear", new ClearPasswordSpec("pencil".toCharArray()));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost",
                Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

        byte[] message = "n,a=user,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        //         c="n,a=user,"
        message = "c=bixhPXVzZXIs,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=NdEpo1qMJaCn9xyrYplfuEKubqQ="
                .getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=n1qgUn3vi9dh7nG1+Giie5qsaVQ=", new String(message));

        assertTrue(saslServer.isComplete());
    }

    /**
     * Test rejection of unauthorized authorization id
     */
    @Test
    public void testUnallowedAuthorizationId() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        CallbackHandler cbh = new ServerCallbackHandler("user", "clear", new ClearPasswordSpec("pencil".toCharArray()));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost",
                Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

        byte[] message = "n,a=admin,n=user,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
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
    public void testMismatchedAuthorizationId() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        CallbackHandler cbh = new ServerCallbackHandler("user", "clear", new ClearPasswordSpec("pencil".toCharArray()));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost",
                Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

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
     * Test rejection of correct credentials and non-corresponding nonce
     */
    @Test
    public void testDifferentNonceAttack() throws Exception {
        mockNonceSalt("differentNonceVs7j", "4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        CallbackHandler cbh = new ServerCallbackHandler("user", "clear", new ClearPasswordSpec("pencil".toCharArray()));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "test", "localhost",
                Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

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
     * Test authentication with unusual characters in credentials (quoting of "n" and "a")
     */
    @Test
    public void testStrangeCredentials() throws Exception {
        mockNonceSalt("3rfcNHYJY1ZVvWVs7j","4125c247e43ab1e93c6dff76");

        final SaslServerFactory serverFactory = obtainSaslServerFactory(ScramSaslServerFactory.class);
        assertNotNull(serverFactory);

        CallbackHandler cbh = new ServerCallbackHandler("strange=user, \\\u0438\u4F60\uD83C\uDCA1", "clear", new ClearPasswordSpec("strange=password, \\\u0438\u4F60\uD83C\uDCA1".toCharArray()));
        final SaslServer saslServer = serverFactory.createSaslServer(Scram.SCRAM_SHA_1, "protocol", "server", Collections.emptyMap(), cbh);
        assertNotNull(saslServer);
        assertTrue(saslServer instanceof ScramSaslServer);

        byte[] message = "n,,n=strange=3Duser=2C \\\u0438\u4F60\uD83C\uDCA1,r=fyko+d2lbbFgONRv9qkxdawL".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", new String(message));

        message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=AAnSTGiu2SSEn7Hkxi6+CXBpLc8=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=jqnGKIvKrX0ER+X58AQ4PsRQl20=", new String(message)); // not verified

        assertTrue(saslServer.isComplete());
    }

}
