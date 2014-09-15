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

package org.wildfly.security.sasl.gssapi.compatibility;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.junit.Test;
import org.wildfly.security.sasl.util.HexConverter;

/**
 * Test authentication (auth) without mutual authentication.
 * <p/>
 * Need not to be tested with auth-int or auth-conf, because this combination is not allowed.
 */
public class NoServerAuthTest extends AbstractTest {

    @Test
    public void testAuth() throws Exception {

        client = Subject.doAs(clientSubject, new PrivilegedExceptionAction<SaslClient>() {
            public SaslClient run() throws Exception {
                SaslClientFactory factory = findSaslClientFactory(wildfly);
                Map<String, String> props = new HashMap<String, String>();
                props.put(Sasl.QOP, "auth");
                props.put(Sasl.SERVER_AUTH, Boolean.toString(false));
                props.put(Sasl.MAX_BUFFER, Integer.toString(0)); // required for JDK implementation
                return factory.createSaslClient(new String[]{"GSSAPI"}, null, "sasl", "test_server_1", props, new NoCallbackHandler());
            }
        });

        server = Subject.doAs(serverSubject, new PrivilegedExceptionAction<SaslServer>() {
            public SaslServer run() throws Exception {
                SaslServerFactory factory = findSaslServerFactory(wildfly);
                Map<String, String> props = new HashMap<String, String>();
                props.put(Sasl.QOP, "auth");
                props.put(Sasl.MAX_BUFFER, Integer.toString(0)); // required for JDK implementation
                return factory.createSaslServer("GSSAPI", "sasl", "test_server_1", props, new AuthorizeOnlyCallbackHandler());
            }
        });

        assertTrue(client.hasInitialResponse());

        exchange = new byte[0];
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("6082020406092a864886f71201020201006e8201f3308201efa003020105a10302010ea20703050000000000a382010b6182010730820103a003020105a10d1b0b57494c44464c592e4f5247a220301ea003020100a11730151b047361736c1b0d746573745f7365727665725f31a381ca3081c7a003020110a281bf0481bc093d7ffd9e956da2c6f5dabb2b41e5ea0b0fc158da3b4f4258baabbf6eabc23e7fe31a65e09a73bfec3c754ee262af1777b9979d2e22eb9e9d8482b8bd40847667cdaa0d67486d5c88e8c65b26df3c6eda36cb36158ad108a0ed6153ea29e8865a9099b53e2d11e90b8c0dd82e18ea982c0e741bbc0e358fbc677b02dd6c4fa7f196f23d7d48f3f82fcd003164852af47f473e44f394d26cbeed416dab4a5225d23de3d7f8109b1c607c535bf5b128210ab54aa115a306786461ddc8a481ca3081c7a003020110a281bf0481bc417f7d7dbafefd13eb5d70b31fd7fe22c4f11c3805da0bb7232fcabc0fa63071aa7b5f7201aa4221f6314c1d71876d3854ae6c46dc39392977b434817b4ca7efdb28a7e96df0f495a18e926879ecd54e6e681e4a56313b0da0063d6dbeca6d396b66419b927db19a92721de01c23def9c35a09b17d95dd9aecdb95959604aa3b0f0af723b879cb453e86aebd1a158d02c3ced2a463b14c7293fd67e12edd29e76bc44542c73373a0726e375d537deec5ceedea43f847c44a9e72a43c", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffffd02408fccf9b1f933b1049d28cf48a5f9d37880ed47be7087ec0b5df07651ec33b1c372e0100000004040404", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffffcf1ccc5848d6e49be1516fd212958c07df8928c349508c7f406811abf0e989a5814f8baa0100000004040404", HexConverter.convertToHexString(exchange));
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

}
