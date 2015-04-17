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

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Random;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.sasl.test.BaseTestCase;
import org.wildfly.security.sasl.test.ClientCallbackHandler;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;

/**
 * Test of client side of SCRAM mechanism.
 * JMockit ensure same generated nonce in every test run.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class ScramClientCompatibilityTest extends BaseTestCase {

    private void mockNonce(final String nonce){
        new MockUp<ScramUtil>(){
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

        CallbackHandler cbh = new ClientCallbackHandler("user", "pencil".toCharArray());
        final SaslClient saslClient = clientFactory.createSaslClient(new String[] { Scram.SCRAM_SHA_1 }, null, "protocol", "localhost", Collections.emptyMap(), cbh);
        assertNotNull(saslClient);
        assertTrue(saslClient instanceof ScramSaslClient);

        byte[] message = AbstractSaslParticipant.NO_BYTES;
        message = saslClient.evaluateChallenge(message);
        assertEquals("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", new String(message));

        message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);
        assertEquals("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", new String(message));

        message = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=".getBytes(StandardCharsets.UTF_8);
        message = saslClient.evaluateChallenge(message);

        assertTrue(saslClient.isComplete());
    }

}
