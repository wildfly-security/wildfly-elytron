/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.audit.ElytronMessages.audit;

import java.io.IOException;
import java.net.InetAddress;
import java.net.PortUnreachableException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.logging.ErrorManager;
import java.util.logging.Level;

import org.jboss.logmanager.ExtLogRecord;
import org.jboss.logmanager.handlers.SyslogHandler;
import org.jboss.logmanager.handlers.SyslogHandler.Facility;
import org.jboss.logmanager.handlers.SyslogHandler.Protocol;
import org.jboss.logmanager.handlers.TcpOutputStream;

import javax.net.SocketFactory;

/**
 * An audit endpoint that logs to syslog server.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SyslogAuditEndpoint implements AuditEndpoint {

    private volatile boolean accepting = true;

    private final SyslogHandler syslogHandler;
    private final TransportErrorManager errorManager;
    private final SyslogHandler.Protocol protocol;
    private final int maxReconnectAttempts;
    private final TcpOutputStream tcpOutputStream;
    private static final int INFINITE_RECONNECT_ATTEMPTS_OVERFLOW_NUMBER;
    static {
        INFINITE_RECONNECT_ATTEMPTS_OVERFLOW_NUMBER = AccessController.doPrivileged(new PrivilegedAction<Integer>() {
            @Override
            public Integer run() {
                return Integer.parseInt(System.getProperty("wildfly.elytron.infinite.reconnect.attempts.overflow.number", "10000"));
            }
        });
    }
    private int currentReconnectAttempts = 0;

    /**
     * Creates a new audit endpoint that logs to syslog server.
     */
    SyslogAuditEndpoint(Builder builder) throws IOException {
        maxReconnectAttempts = builder.maxReconnectAttempts;
        protocol = builder.ssl ? Protocol.SSL_TCP : builder.tcp ? Protocol.TCP : Protocol.UDP;
        syslogHandler = new SyslogHandler(checkNotNullParam("serverAddress", builder.serverAddress), builder.port, Facility.SECURITY,
                builder.format, protocol, checkNotNullParam("hostName", builder.hostName));

        if (builder.tcp) {
            // This is not the ideal way to handle it, but with the current state of the log manager we need to keep an
            // accurate count of the failures. We'll use our own TcpOutputStream so we can use the
            // TcpOutputStream.isConnected() method to determine if the stream is connected or not.
            if (builder.socketFactory != null) {
                tcpOutputStream = new TcpOutputStream(builder.socketFactory, builder.serverAddress, builder.port) {
                    // anonymous class to access protected constructor
                };
            } else {
                tcpOutputStream = new TcpOutputStream(builder.serverAddress, builder.port);
            }
            syslogHandler.setOutputStream(tcpOutputStream);
        } else {
            tcpOutputStream = null;
        }
        errorManager = new TransportErrorManager(protocol);
        syslogHandler.setErrorManager(errorManager);
        accept(EventPriority.INFORMATIONAL, "Elytron audit logging enabled with RFC format: " + builder.format);
    }

    @Override
    public void accept(EventPriority priority, String message) throws IOException {
        if (!accepting) return;

        synchronized (this) {
            if (!accepting) return;
            // Ensure that the handler stops trying to connect if the thread is interrupted
            if (Thread.currentThread().isInterrupted()) {
                syslogHandler.close();
                return;
            }
            try {
                tryPublish(priority, message);
                if (tcpOutputStream == null) {
                    // This must be a UDP stream so we can assume a successful message was sent and reset the reconnect
                    // attempts.
                    currentReconnectAttempts = 0;
                } else {
                    // If the TCP stream is now connected we can reset the reconnect attempts.
                    if (tcpOutputStream.isConnected()) {
                        currentReconnectAttempts = 0;
                    } else {
                        checkAttempts();
                    }
                }
            } catch (IOException e) {
                checkAttempts();
                // TcpOutputStream has its' own reconnect handler, so just throw the error
                if (protocol != Protocol.UDP) {
                    throw e;
                }

                // Infinite reconnect attempts so just eat the error
                audit.tracef(e, "Unable to send message on %d try.",  currentReconnectAttempts);
            }
        }
    }

    private void checkAttempts() throws IOException {
        if (accepting) {
            if (currentReconnectAttempts == maxReconnectAttempts) {
                close();
                throw audit.syslogMaximumReconnectAttemptsReached(currentReconnectAttempts);
            } else if (maxReconnectAttempts != -1) {
                // Reconnect attempts are less than max so eat the error
                currentReconnectAttempts++;
            } else {
                if (currentReconnectAttempts < INFINITE_RECONNECT_ATTEMPTS_OVERFLOW_NUMBER) {
                    currentReconnectAttempts++;
                }
            }
        }
    }

    /**
     * Gets the current amount of reconnect attempts, with -1 signifying that the value for infinite reconnect attempts
     * case has overflowed the maximum allowed amount
     *
     * @return The current reconnect attempts, or -1 if the maximum tracked value for infinite attempts has overflowed
     */
    public int getAttempts() {
        if (maxReconnectAttempts != -1) {
            return currentReconnectAttempts;
        } else {
            return currentReconnectAttempts == INFINITE_RECONNECT_ATTEMPTS_OVERFLOW_NUMBER ? -1 : currentReconnectAttempts;
        }
    }

    private static Level toLevel(EventPriority eventPriority) {
        switch (eventPriority) {
            case ALERT:
            case EMERGENCY:
            case CRITICAL:
            case ERROR:
                return Level.SEVERE;
            case WARNING:
                return Level.WARNING;
            case INFORMATIONAL:
                return Level.INFO;
            case OFF:
                throw audit.invalidEventPriority(eventPriority);
            default:
                return Level.FINEST;
        }
    }

    @Override
    public void close() throws IOException {
        accepting = false;

        synchronized(this) {
            syslogHandler.close();
        }
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link SyslogAuditEndpoint}.
     *
     * @return a new {@link Builder} capable of building a {@link SyslogAuditEndpoint}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for syslog audit endpoint.
     */
    public static class Builder {

        private InetAddress serverAddress;
        private int port;
        private boolean ssl = false;
        private boolean tcp = true;
        private String hostName;
        private SocketFactory socketFactory = null;
        private SyslogHandler.SyslogType format = SyslogHandler.SyslogType.RFC5424;
        private int maxReconnectAttempts = 0;

        Builder() {
        }

        /**
         * Set the server address syslog messages should be sent to.
         *
         * @param serverAddress the server address syslog messages should be sent to.
         * @return this builder.
         */
        public Builder setServerAddress(InetAddress serverAddress) {
            this.serverAddress = checkNotNullParam("serverAddress", serverAddress);

            return this;
        }

        /**
         * Set the port the syslog server is listening on.
         *
         * @param port the port the syslog server is listening on.
         * @return this builder.
         */
        public Builder setPort(int port) {
            this.port = port;

            return this;
        }

        /**
         * Set if the communication should be using TCP.
         *
         * @param tcp if the communication should be using TCP.
         * @return this builder.
         */
        public Builder setTcp(boolean tcp) {
            this.tcp = tcp;

            return this;
        }

        /**
         * Set if the communication should be using SSL.
         *
         * @param ssl if the communication should be using SSL.
         * @return this builder.
         */
        public Builder setSsl(boolean ssl) {
            this.ssl = ssl;

            return this;
        }

        /**
         * Set {@link SocketFactory} for TCP connections - usually to provide configured {@link javax.net.ssl.SSLSocketFactory}.
         *
         * @param socketFactory the {@link SocketFactory} or {@code null} for default {@link SocketFactory}.
         * @return this builder.
         */
        public Builder setSocketFactory(SocketFactory socketFactory) {
            this.socketFactory = socketFactory;

            return this;
        }

        /**
         * Set the host name that should be sent within the syslog messages.
         *
         * @param hostName the host name that should be sent within the syslog messages.
         * @return this builder.
         */
        public Builder setHostName(String hostName) {
            this.hostName = checkNotNullParam("hostName", hostName);

            return this;
        }

        /**
         * Sets the SyslogFormat that will be used.
         *
         * @param format The SyslogFormat that should be used
         * @return this builder.
         */
        public Builder setFormat(SyslogHandler.SyslogType format) {
            this.format = checkNotNullParam("format", format);

            return this;
        }

        /**
         * Sets the amount of reconnect-attempts that will be used.
         *
         * @param maxReconnectAttempts The maximum number of reconnect-attempts attempts with:
         * -1 meaning indefinite attempts
         * 0 meaning no attempts
         * Any positive integer meaning that number of attempts
         * @exception IllegalArgumentException throws an error in the case of a bad reconnect-attempts value of &lt; -1
         * @return this builder.
         */
        public Builder setMaxReconnectAttempts(int maxReconnectAttempts) throws IllegalArgumentException {
            if (maxReconnectAttempts < -1) {
                throw audit.badReconnectAttemptsNumber(maxReconnectAttempts);
            }
            this.maxReconnectAttempts = maxReconnectAttempts;

            return this;
        }

        /**
         * Build a new {@link AuditEndpoint} configured to pass all messages using Syslog.
         *
         * @return a new {@link AuditEndpoint} configured to pass all messages using Syslog.
         * @throws IOException if an error occurs initialising the endpoint.
         */
        public AuditEndpoint build() throws IOException {
            return new SyslogAuditEndpoint(this);
        }

    }

    private class TransportErrorManager extends ErrorManager {
        private volatile Exception error;
        private Protocol transport;

        public TransportErrorManager(Protocol transport) {
            this.transport = transport;
        }

        @Override
        public synchronized void error(String msg, Exception ex, int code) {
            error = ex;
        }

        void getAndThrowError() throws IOException {
            Exception error = this.error;
            this.error = null;

            if (error != null) {
                throwAsIoOrRuntimeException(error);
            }
        }

        void throwAsIoOrRuntimeException(Throwable t) throws IOException {
            if (t instanceof PortUnreachableException && transport == Protocol.UDP) {
                throw audit.udpPortUnavailable(t.getCause());
            }
            if (t instanceof IOException) {
                throw (IOException)t;
            }
            if (t instanceof RuntimeException) {
                throw (RuntimeException)t;
            }
            throw new RuntimeException(t);
        }
    }

    private void tryPublish(EventPriority priority, String message) throws IOException {
        syslogHandler.doPublish(new ExtLogRecord(toLevel(priority), message, SyslogAuditEndpoint.class.getName()));
        errorManager.getAndThrowError();
    }
}
