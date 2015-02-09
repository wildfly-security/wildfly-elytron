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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.HashMap;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

import org.jboss.logging.Logger;
import org.junit.Test;

/**
 * Tests of Gssapi helpers (don't require started kerberos server)
 */
public class GssapiUtilUnitTest extends AbstractGssapiMechanism {

    public GssapiUtilUnitTest() throws SaslException {
        super("sasl", "imap", "test_server_1", new HashMap<String, String>(), new CallbackHandler(){
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                throw new UnsupportedCallbackException(callbacks[0]);
            }
        }, Logger.getLogger(GssapiUtilUnitTest.class));
    }

    @Override
    protected byte[] evaluateMessage(int state, final byte[] message) throws SaslException {
        return null;
    }

    @Test
    public void testIntToNetworkOrderBytes() throws Exception {
        assertArrayEquals("JDK maxbuf", new byte[]{(byte)0x01,(byte)0x00,(byte)0x00}, intToNetworkOrderBytes(65536));
        assertArrayEquals("WildFly maxbuf", new byte[]{(byte)0x00,(byte)0x0F,(byte)0xBA}, intToNetworkOrderBytes(4026));
        assertArrayEquals("minimum", new byte[]{(byte)0x00,(byte)0x00,(byte)0x00}, intToNetworkOrderBytes(0));
        assertArrayEquals("maximum", new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF}, intToNetworkOrderBytes(16777215));
        assertArrayEquals("bytes", new byte[]{(byte)0x83,(byte)0x82,(byte)0x81}, intToNetworkOrderBytes(8618625));
    }

    @Test
    public void testNetworkOrderBytesToInt(){
        assertEquals("JDK maxbuf", 65536, networkOrderBytesToInt(new byte[]{(byte)0x01,(byte)0x00,(byte)0x00}, 0, 3));
        assertEquals("WildFly maxbuf", 4026, networkOrderBytesToInt(new byte[]{(byte)0x00,(byte)0x0F,(byte)0xBA}, 0, 3));
        assertEquals("minimum", 0, networkOrderBytesToInt(new byte[]{(byte)0x00,(byte)0x00,(byte)0x00}, 0, 3));
        assertEquals("one", 1, networkOrderBytesToInt(new byte[]{(byte)0x00,(byte)0x00,(byte)0x01}, 0, 3));
        assertEquals("255", 255, networkOrderBytesToInt(new byte[]{(byte)0x00,(byte)0x00,(byte)0xFF}, 0, 3));
        assertEquals("maximum", 16777215, networkOrderBytesToInt(new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF}, 0, 3));
        assertEquals("bytes", 8618625, networkOrderBytesToInt(new byte[]{(byte)0x83,(byte)0x82,(byte)0x81}, 0, 3));
    }

    @Test
    public void testParsePreferredQop() throws Exception {
        assertArrayEquals(new QOP[]{QOP.AUTH}, parsePreferredQop("auth"));
        assertArrayEquals(new QOP[]{QOP.AUTH_INT}, parsePreferredQop("auth-int"));
        assertArrayEquals(new QOP[]{QOP.AUTH_CONF}, parsePreferredQop("auth-conf"));
        assertArrayEquals(new QOP[]{QOP.AUTH,QOP.AUTH_INT,QOP.AUTH_CONF}, parsePreferredQop("auth,auth-int,auth-conf"));
        assertArrayEquals(new QOP[]{QOP.AUTH,QOP.AUTH_INT,QOP.AUTH_CONF}, parsePreferredQop("auth, auth-int, auth-conf"));
        assertArrayEquals(new QOP[]{QOP.AUTH,QOP.AUTH_INT}, parsePreferredQop("\n auth \n,\n auth-int \n"));
        assertArrayEquals(new QOP[]{QOP.AUTH}, parsePreferredQop(null));
    }

}
