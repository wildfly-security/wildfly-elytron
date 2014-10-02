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

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.sasl.util.HexConverter;

public class BasicConfidencyGssapiTest extends AbstractGssapiTest {

    @Test
    public void testAuthConf() throws Exception {

        client = Subject.doAs(clientSubject, new PrivilegedExceptionAction<SaslClient>() {
            public SaslClient run() throws Exception {
                SaslClientFactory factory = findSaslClientFactory(wildfly);
                Map<String, String> props = new HashMap<String, String>();
                props.put(Sasl.QOP, "auth-conf");
                props.put(Sasl.SERVER_AUTH, Boolean.toString(true));
                props.put(Sasl.MAX_BUFFER, Integer.toString(61234));
                return factory.createSaslClient(new String[]{"GSSAPI"}, null, "sasl", "test_server_1", props, new NoCallbackHandler());
            }
        });

        server = Subject.doAs(serverSubject, new PrivilegedExceptionAction<SaslServer>() {
            public SaslServer run() throws Exception {
                SaslServerFactory factory = findSaslServerFactory(wildfly);
                Map<String, String> props = new HashMap<String, String>();
                props.put(Sasl.QOP, "auth-conf");
                props.put(Sasl.MAX_BUFFER, Integer.toString(64321));
                return factory.createSaslServer("GSSAPI", "sasl", "test_server_1", props, new AuthorizeOnlyCallbackHandler());
            }
        });

        assertTrue(client.hasInitialResponse());

        exchange = new byte[0];
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("6082020406092a864886f71201020201006e8201f3308201efa003020105a10302010ea20703050020000000a382010b6182010730820103a003020105a10d1b0b57494c44464c592e4f5247a220301ea003020100a11730151b047361736c1b0d746573745f7365727665725f31a381ca3081c7a003020110a281bf0481bc093d7ffd9e956da2c6f5dabb2b41e5ea0b0fc158da3b4f4258baabbf6eabc23e7fe31a65e09a73bfec3c754ee262af1777b9979d2e22eb9e9d8482b8bd40847667cdaa0d67486d5c88e8c65b26df3c6eda36cb36158ad108a0ed6153ea29e8865a9099b53e2d11e90b8c0dd82e18ea982c0e741bbc0e358fbc677b02dd6c4fa7f196f23d7d48f3f82fcd003164852af47f473e44f394d26cbeed416dab4a5225d23de3d7f8109b1c607c535bf5b128210ab54aa115a306786461ddc8a481ca3081c7a003020110a281bf0481bc417f7d7dbafefd13eb5d70b31fd7fe22c4f11c3805da0bb7232fcabc0fa63071aa7b5f7201aa4221f6314c1d71876d3854ae6c46dc39392977b434817b4ca7efdb28a7e96df0f495a18e926879ecd54e6e681e4a56313b0d70068cf78988e590461540f3535e4cb0baa7c3a8df84d5f8cdf956ac4cbdd51cb6b8d8ab598b5f0bfb53321f2a023dac159e493b396d3205bde177d30bf619c5278859c2832367307b3e29c2ab2b6d1884d3696c9cb7dc12de0c4174d933c361d618f658", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("606c06092a864886f71201020202006f5d305ba003020105a10302010fa24f304da003020110a2460444cad60460dc79a055e9ed878bd80cb136baec236919258d370a9442465555054f5a09ccce3aeaf1ac6d5ddc3e4b207d06da2c85735410bff2cefa402a7c83501c24148aba", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffff53696fad43cf3605bb6bf692ba0297db2f1760e16a8864dc13e32acd54a3cdbfe27f3ff20400fb4104040404", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertFalse(client.isComplete());

        exchange = evaluateByClient(exchange);
        assertEquals("603f06092a864886f71201020202010400ffffffff209a962fae641a9fef596b5c0c9aa315149e9f1fa35b6124dc1f1b7d944635cbec6548270400ef3204040404", HexConverter.convertToHexString(exchange));
        assertFalse(server.isComplete());
        assertTrue(client.isComplete());

        exchange = evaluateByServer(exchange);
        assertEquals(null, exchange);
        assertTrue(server.isComplete());
        assertTrue(client.isComplete());
        assertEquals("jduke@WILDFLY.ORG", server.getAuthorizationID());
        assertEquals("auth-conf", server.getNegotiatedProperty(Sasl.QOP));
        assertEquals("auth-conf", client.getNegotiatedProperty(Sasl.QOP));
        assertEquals("64321", server.getNegotiatedProperty(Sasl.MAX_BUFFER)); // max length of received message before unwrapping
        assertEquals("61234", client.getNegotiatedProperty(Sasl.MAX_BUFFER));
        assertEquals("61165", server.getNegotiatedProperty(Sasl.RAW_SEND_SIZE)); // max length of sent message before wrapping
        assertEquals("64252", client.getNegotiatedProperty(Sasl.RAW_SEND_SIZE));

        message = new byte[]{(byte)0x00,(byte)0x12,(byte)0x34,(byte)0x56,(byte)0x78,(byte)0x9A,(byte)0xBC,(byte)0xDE,(byte)0xFF};
        wrappedMessage = server.wrap(message, 0, message.length);
        assertEquals("604706092a864886f712010202020104000200ffffe95b9a1821e8ed3d21b4abf3c62ca45e92638a381552f56e5ef247fac3b40bc614e465f25d2e30dd445266bbc5c648fcd2a124fc", HexConverter.convertToHexString(wrappedMessage));

        message = client.unwrap(wrappedMessage, 0, wrappedMessage.length);
        Assert.assertArrayEquals(message, new byte[]{(byte)0x00,(byte)0x12,(byte)0x34,(byte)0x56,(byte)0x78,(byte)0x9A,(byte)0xBC,(byte)0xDE,(byte)0xFF});

        message = new byte[]{(byte)0xFF,(byte)0xED,(byte)0xCB,(byte)0xA9,(byte)0x87,(byte)0x65,(byte)0x43,(byte)0x21,(byte)0x00};
        wrappedMessage = client.wrap(message, 0, message.length);
        assertEquals("604706092a864886f712010202020104000200ffffea352a02de5169baaac0987aea3014538c86ff1023da61a2023677386011794e02afb3dd0bf2722d361e1eec5037ab9ba101f3ee", HexConverter.convertToHexString(wrappedMessage));

        message = server.unwrap(wrappedMessage, 0, wrappedMessage.length);
        Assert.assertArrayEquals(message, new byte[]{(byte)0xFF,(byte)0xED,(byte)0xCB,(byte)0xA9,(byte)0x87,(byte)0x65,(byte)0x43,(byte)0x21,(byte)0x00});

    }

}
