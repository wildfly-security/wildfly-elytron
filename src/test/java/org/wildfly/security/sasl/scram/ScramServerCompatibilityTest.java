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

package org.wildfly.security.sasl.scram;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Random;

import javax.security.auth.callback.CallbackHandler;
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
import org.wildfly.security.sasl.util.HexConverter;

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
                return HexConverter.convertFromHex(salt);
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

        message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=".getBytes(StandardCharsets.UTF_8);
        message = saslServer.evaluateResponse(message);
        assertEquals("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", new String(message));

        assertTrue(saslServer.isComplete());
    }

}
