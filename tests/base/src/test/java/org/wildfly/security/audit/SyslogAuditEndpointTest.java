/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.audit;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;

import javax.net.SocketFactory;

import org.apache.commons.lang3.SystemUtils;
import org.jboss.logmanager.handlers.SyslogHandler;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Test cases to test {@link SyslogAuditEndpoint}
 *
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public class SyslogAuditEndpointTest {
    private static final String HOST_NAME = "localhost";
    private static final String BAD_HOST_NAME = "0.35.98.76";
    private static final String RFC3164_LOG_MESSAGE = "testing log message RFC3164";
    private static final String RFC5424_LOG_MESSAGE = "testing log message RFC5424";
    private static final int UDP_PORT = 10837;
    private static final int TCP_PORT = 10857;
    private static final int RECONNECT_NUMBER = 10;
    private static final int BAD_RECONNECT_NUMBER = -2;
    private static final int RECONNECT_TIMEOUT = 450;
    private static SocketFactory socketFactory = null;
    private static SimpleSyslogServer udpServer = null;
    private static SimpleSyslogServer tcpServer = null;
    private String failString = "";

    /**
     * Gets the server address and makes the socket factory before starting up the server
     */
    @BeforeClass
    public static void initializeServer() throws Exception {
        socketFactory = SocketFactory.getDefault();
        udpServer = SimpleSyslogServer.createUdp(UDP_PORT);
        tcpServer = SimpleSyslogServer.createTcp(TCP_PORT, false);
    }

    /**
     * Safely shutdowns the server
     */
    @AfterClass
    public static void shutdownServer() {
        udpServer.close();
        tcpServer.close();
    }

    /**
     * Tests the syslog audit endpoint with RFC 3164 format and critical priority
     */
    @Test
    public void testGenericRfc3164SyslogEvent() throws Exception {
        AuditEndpoint endpoint = setupEndpointUdp(SyslogHandler.SyslogType.RFC3164);
        endpoint.accept(EventPriority.CRITICAL, RFC3164_LOG_MESSAGE);
        endpoint.close();
        discardMessage(udpServer);
        verifyUdpMessage(RFC3164_LOG_MESSAGE);
    }

    /**
     * Tests the syslog audit endpoint with RFC 5424 format and critical priority
     */
    @Test
    public void testGenericRfc5424SyslogEvent() throws Exception {
        AuditEndpoint endpoint = setupEndpointUdp(SyslogHandler.SyslogType.RFC5424);
        endpoint.accept(EventPriority.CRITICAL, RFC5424_LOG_MESSAGE);
        endpoint.close();
        discardMessage(udpServer);
        verifyUdpMessage(RFC5424_LOG_MESSAGE);
    }

    /**
     * Tests that the endpoint rejects a bad integer
     */
    @Test
    public void testBadIntegerReconnectAttempts() throws Exception {
        try {
            // Since the endpoint gives a message upon creation there is no need to call .accept()
            AuditEndpoint endpoint = setupEndpointBadUdpReconnectAttempts(BAD_RECONNECT_NUMBER);
            Assert.fail("No error was thrown while attempting to log with an invalid reconnect-attempts number.");
        } catch (IllegalArgumentException e) {
            assertCorrectError(e, new String[] {"ELY12000", Integer.toString(BAD_RECONNECT_NUMBER)});
        }
    }

    /**
     * Tests that the server continuously attempts to resend the message for {@link SyslogAuditEndpointTest#RECONNECT_TIMEOUT} milliseconds
     */
    @Test
    @Ignore("[ELY-1895] Testing of failures is unreliable.")
    public void testFailureInfiniteReconnectAttempts() throws Exception {
        // Windows Server can have an issue echoing back an error, causing the test to fail by not seeing a failure sending
        Assume.assumeFalse("Test does not run on Windows Server", SystemUtils.OS_NAME.contains("Windows Server"));
        Thread t = new Thread(() -> {
            try {
                // Since the endpoint gives a message upon creation there is no need to call .accept()
                SyslogAuditEndpoint endpoint = (SyslogAuditEndpoint) setupEndpointBadUdpReconnectAttempts(-1);
                int attemptNumber = 1;
                int currentAttempts = endpoint.getAttempts();
                while(attemptNumber == currentAttempts || currentAttempts == -1) {
                    endpoint.accept(EventPriority.INFORMATIONAL, "This is a test message that should fail.");
                    currentAttempts = endpoint.getAttempts();
                    if (currentAttempts != -1) {
                        attemptNumber++;
                    }
                    if (Thread.currentThread().isInterrupted()) {
                        break;
                    }
                }
                if (!Thread.currentThread().isInterrupted()) {
                    this.failString = "No error was thrown while attempting to log to a bad IP with UDP.";
                }
            } catch (Exception e) {
                this.failString = "An unexpected error has occurred: " + e.getMessage();
            }
        });
        t.start();
        Thread.sleep(RECONNECT_TIMEOUT);
        t.interrupt();
        t.join();
        if (!failString.isEmpty()) {
            Assert.fail(failString);
        }
    }

    /**
     * Tests that the server never reattempts to send the message
     */
    @Test
    @Ignore("[ELY-1895] Testing of failures is unreliable.")
    public void testFailureZeroReconnectAttempts() throws Exception {
        // Windows Server can have an issue echoing back an error, causing the test to fail by not seeing a failure sending
        Assume.assumeFalse("Test does not run on Windows Server", SystemUtils.OS_NAME.contains("Windows Server"));
        try {
            // Since the endpoint gives a message upon creation there is no need to call .accept()
            AuditEndpoint endpoint = setupEndpointBadUdpReconnectAttempts(0);
            Assert.fail("No error was thrown while attempting to log to a bad IP with UDP.");
        } catch (IOException e) {
            assertCorrectError(e, new String[] {"ELY12001", "0"});
        }
    }

    /**
     * Tests that the server reattempts to send the message {@link SyslogAuditEndpointTest#RECONNECT_NUMBER} times
     */
    @Test
    @Ignore("[ELY-1895] Testing of failures is unreliable.")
    public void testFailureNumberedReconnectAttempts() throws Exception {
        // Windows Server can have an issue echoing back an error, causing the test to fail by not seeing a failure sending
        Assume.assumeFalse("Test does not run on Windows Server", SystemUtils.OS_NAME.contains("Windows Server"));
        try {
            // Since the endpoint gives a message upon creation there is no need to call .accept()
            AuditEndpoint endpoint = setupEndpointBadUdpReconnectAttempts(RECONNECT_NUMBER);
            for (int i = 0; i < RECONNECT_NUMBER; i++) {
                endpoint.accept(EventPriority.INFORMATIONAL, "This is a test message that should fail.");
            }
            Assert.fail("No error was thrown while attempting to log to a bad IP with UDP.");
        } catch (IOException e) {
            assertCorrectError(e, new String[] {"ELY12001", Integer.toString(RECONNECT_NUMBER)});
        }
    }

    /**
     * Tests that the server successfully sends a message with reconnect-attempts set to infinite
     */
    @Test
    public void testSuccessInfiniteReconnectAttempts() throws Exception {
        AuditEndpoint endpoint = setupEndpointUdpReconnectAttempts(-1);
        endpoint.accept(EventPriority.CRITICAL, RFC5424_LOG_MESSAGE);
        endpoint.close();
        discardMessage(udpServer);
        verifyUdpMessage(RFC5424_LOG_MESSAGE);
    }

    /**
     * Tests that the server successfully sends a message with reconnect-attempts set to zero
     */
    @Test
    public void testSuccessZeroReconnectAttempts() throws Exception {
        AuditEndpoint endpoint = setupEndpointUdpReconnectAttempts(0);
        endpoint.accept(EventPriority.CRITICAL, RFC5424_LOG_MESSAGE);
        endpoint.close();
        discardMessage(udpServer);
        verifyUdpMessage(RFC5424_LOG_MESSAGE);
    }

    /**
     * Tests that the server successfully sends a message with reconnect-attempts set to {@link SyslogAuditEndpointTest#RECONNECT_NUMBER}
     */
    @Test
    public void testSuccessNumberedReconnectAttempts() throws Exception {
        AuditEndpoint endpoint = setupEndpointUdpReconnectAttempts(RECONNECT_NUMBER);
        endpoint.accept(EventPriority.CRITICAL, RFC5424_LOG_MESSAGE);
        endpoint.close();
        discardMessage(udpServer);
        verifyUdpMessage(RFC5424_LOG_MESSAGE);
    }

    /**
     * Tests that the server successfully sends a message with TCP Protocol
     */
    @Test
    public void testSuccessTcp() throws Exception {
        AuditEndpoint endpoint = setupEndpointTcp();
        endpoint.accept(EventPriority.CRITICAL, RFC5424_LOG_MESSAGE);
        endpoint.close();
        verifyTcpMessage(RFC5424_LOG_MESSAGE);
    }

    /**
     * Setups the Elytron Audit Logging Endpoint
     *
     * @param syslogFormat The syslog format to use
     * @return The audit endpoint
     */
    private AuditEndpoint setupEndpoint(SyslogHandler.SyslogType syslogFormat, String hostName, int port, boolean ssl, boolean tcp, int maxReconnectAttempts) throws Exception {
        return SyslogAuditEndpoint.builder()
                .setFormat(syslogFormat)
                .setHostName(hostName)
                .setPort(port)
                .setServerAddress(InetAddress.getByName(hostName))
                .setSocketFactory(socketFactory)
                .setSsl(ssl)
                .setTcp(tcp)
                .setMaxReconnectAttempts(maxReconnectAttempts)
                .build();
    }

    /**
     * Sets up the endpoint with UDP protocol
     *
     * @param syslogFormat The syslog format to use
     * @return The audit endpoint
     */
    private AuditEndpoint setupEndpointUdp(SyslogHandler.SyslogType syslogFormat) throws Exception {
        return setupEndpoint(syslogFormat, HOST_NAME, UDP_PORT, false, false, -1);
    }

    /**
     * Sets up the endpoint with TCP protocol
     *
     * @return The audit endpoint
     */
    private AuditEndpoint setupEndpointTcp() throws Exception {
        return setupEndpoint(SyslogHandler.SyslogType.RFC5424, HOST_NAME, TCP_PORT, false, true, 0);
    }

    /**
     * Sets up the endpoint with UDP protocol
     *
     * @param maxReconnectAttempts The amount of reconnect-attempts that should be used
     * @return The audit endpoint
     */
    private AuditEndpoint setupEndpointUdpReconnectAttempts(int maxReconnectAttempts) throws Exception {
        return setupEndpoint(SyslogHandler.SyslogType.RFC5424, HOST_NAME, UDP_PORT, false, false, maxReconnectAttempts);
    }

    /**
     * Sets up the endpoint with UDP protocol and RFC5424 and an invalid host name
     *
     * @param maxReconnectAttempts The amount of reconnect-attempts that should be used
     * @return The audit endpoint
     */
    private AuditEndpoint setupEndpointBadUdpReconnectAttempts(int maxReconnectAttempts) throws Exception {
        return setupEndpoint(SyslogHandler.SyslogType.RFC5424, BAD_HOST_NAME, UDP_PORT, false, false, maxReconnectAttempts);
    }

    /**
     * Discards a message from the server
     *
     * @param server The syslog server to use for receiving the message
     */
    private void discardMessage(SimpleSyslogServer server) throws Exception {
        server.receiveData();
    }

    /**
     * Receives the message from the server and verifies it matches the test case
     *
     * @param server The syslog server to use for receiving the message
     * @param msg The expected test message
     */
    private void verifyMessage(SimpleSyslogServer server, String msg) throws Exception {
        byte[] serverData = server.receiveData();
        String[] rawServerDataString = new String(serverData).split(System.getProperty("line.separator"));
        for (String serverDataString : rawServerDataString) {
            if (serverDataString.contains(msg)) {
                return;
            }
        }
        Assert.fail("Server message is not the test message");
    }

    /**
     * Receives the message from the udp server and verifies it matches the test case
     *
     * @param msg The expected test message
     */
    private void verifyUdpMessage(String msg) throws Exception {
        verifyMessage(udpServer, msg);
    }

    /**
     * Receives the message from the tcp server and verifies it matches the test case
     *
     * @param msg The expected test message
     */
    private void verifyTcpMessage(String msg) throws Exception {
        verifyMessage(tcpServer, msg);
    }

    /**
     * Asserts that the expected failure happened
     *
     * @param e The expected exception
     * @param messages The array of messages that should be contained in the exception message
     */
    private void assertCorrectError(Exception e, String[] messages) {
        for (String msg : messages) {
            System.out.println(e.getMessage());
            assertTrue(e.getMessage().contains(msg));
        }
    }
}
