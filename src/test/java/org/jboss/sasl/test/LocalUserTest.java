/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.sasl.test;

import java.util.Collections;
import org.junit.Test;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Test for the local user SASL mechanism, this will test both the client and server side.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class LocalUserTest extends BaseTestCase {

    private static final String LOCAL_USER = "JBOSS-LOCAL-USER";
    /*
     *  Normal SASL Client/Server interaction.
     */

    /**
     * Test a successful exchange using the ANONYMOUS mechanism.
     */

    @Test
    public void testSuccessfulExchange() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", (char[]) null);
        SaslServer server = Sasl.createSaslServer(LOCAL_USER, "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", (char[]) null);
        SaslClient client = Sasl.createSaslClient(new String[]{ LOCAL_USER }, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] response = client.evaluateChallenge(new byte[0]);
        byte[] challenge = server.evaluateResponse(response);
        response = client.evaluateChallenge(challenge);
        challenge = server.evaluateResponse(response);
        assertNull(challenge);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }

}
