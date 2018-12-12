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
import static org.wildfly.security.audit._private.ElytronMessages.audit;

import java.io.IOException;
import java.net.InetAddress;
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

    /**
     * Creates a new audit endpoint that logs to syslog server.
     */
    SyslogAuditEndpoint(Builder builder) throws IOException {
        SyslogHandler.Protocol protocol = builder.ssl ? Protocol.SSL_TCP : builder.tcp ? Protocol.TCP : Protocol.UDP;
        syslogHandler = new SyslogHandler(checkNotNullParam("serverAddress", builder.serverAddress), builder.port, Facility.SECURITY,
                null, protocol, checkNotNullParam("hostName", builder.hostName));

        if (builder.tcp && builder.socketFactory != null) {
            syslogHandler.setOutputStream(new TcpOutputStream(builder.socketFactory, builder.serverAddress, builder.port) {
                // anonymous class to access protected constructor
            });
        }
    }

    @Override
    public void accept(EventPriority priority, String message) throws IOException {
        if (!accepting) return;

        synchronized(this) {
            if (!accepting) return;

            syslogHandler.doPublish(new ExtLogRecord(toLevel(priority), message, SyslogAuditEndpoint.class.getName()));
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
         * Build a new {@link AuditEndpoint} configured to pass all messages using Syslog.
         *
         * @return a new {@link AuditEndpoint} configured to pass all messages using Syslog.
         * @throws IOException if an error occurs initialising the endpoint.
         */
        public AuditEndpoint build() throws IOException {
            return new SyslogAuditEndpoint(this);
        }

    }

}
