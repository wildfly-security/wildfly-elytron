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
 * Test authentication without integrity and confidence checking (auth)
 */
public class BasicAuthTest extends AbstractTest {

    @Test
    public void testAuth() throws Exception {

        client = Subject.doAs(clientSubject, new PrivilegedExceptionAction<SaslClient>() {
            public SaslClient run() throws Exception {
                SaslClientFactory factory = findSaslClientFactory(wildfly);
                Map<String, String> props = new HashMap<String, String>();
                props.put(Sasl.QOP, "auth");
                props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
                //props.put(Sasl.MAX_BUFFER, Integer.toString(0)); // required for JDK implementation
                return factory.createSaslClient(new String[]{"GSSAPI"}, null, "sasl", "test_server_1", props, new NoCallbackHandler());
            }
        });

        server = Subject.doAs(serverSubject, new PrivilegedExceptionAction<SaslServer>() {
            public SaslServer run() throws Exception {
                SaslServerFactory factory = findSaslServerFactory(wildfly);
                Map<String, String> props = new HashMap<String, String>();
                props.put(Sasl.QOP, "auth");
                //props.put(Sasl.MAX_BUFFER, Integer.toString(0)); // required for JDK implementation
                return factory.createSaslServer("GSSAPI", "sasl", "test_server_1", props, new AuthorizeOnlyCallbackHandler());
            }
        });

        assertTrue(client.hasInitialResponse());

        exchange = new byte[0];
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("6082020406092a864886f71201020201006e8201f3308201efa003020105a10302010ea20703050020000000a382010b6182010730820103a003020105a10d1b0b57494c44464c592e4f5247a220301ea003020100a11730151b047361736c1b0d746573745f7365727665725f31a381ca3081c7a003020110a281bf0481bc35c0e8fcda8a25bc04a0f0b15bd2007a8eaf706c6e282746f2520a0df3b2981a5c550647ac08cca70c8591e3e9f85c166f0b64a30af8c77b185cc8c3708e6d113ba90fca1a47e21540fedfc8b92e2427e601ba7d6c304483bf43bc85a8efe9936004c5b0132700426dd4427478338a389f6e0dec8125a7ec571859866349f9604730e45373bd956d86814943d8a1b11c9cf5a84c5722a5a665f7705884fc14b0d74c16547c92ec8b561c7c07f7ea6cdea07286ac4c4a2187a15e775da481ca3081c7a003020110a281bf0481bc7b05b4ad61dc02fb178b29d6aa5d79f05ee5d0c23a99204525c4927824b390f5ebd1cadcaa97ead6c3bdaf8c11d6c6e45c7b9270a9ddc44c52c6fe7ac29456590c3981aedc84aaad551dbcec2b9b930841713bff6d18f7df4e7ef27dafd06a60a7c2eeb1c18dd3d49579f98aca996eefda0741a98f2aa3f43328b29273e0c7984add0ebc10d77e11b099f9414d5c2d7330da9dcb090099f9d4985f924c6b524b97078589c10483df52419e2e0a8782f092705cea03807607c1f7c2d5", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("606c06092a864886f71201020202006f5d305ba003020105a10302010fa24f304da003020110a246044489951ebd7508eea04bd5eabd787a6a4870454fe146c0ccc9dad0b54981dd53d075f95f6c132f1d44716091a65428f28ed320cb699d1652f8ebbbe56e5fdc7f52ddff5966", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        // different for JDK and WildFly impl, because JDK sends max buffer size although no security layer offered
        exchange = evaluateByServer(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffffea1e2bf9dcfc44a31342cb16ed4e47a471506ab9e3152854052f6f54e687fe8bc940ea4a0100000004040404", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        // different for JDK and WildFly impl, because JDK sends max buffer size although no security layer offered
        exchange = evaluateByClient(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffffe210a564589f9b536cd37a094a4cf9daf4d82ca5bfd1958c8901f0569cd068a60d1fd2ad0100000004040404", HexConverter.convertToHexString(exchange));
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
