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

package org.wildfly.security.sasl.proxy;

import static org.wildfly.security._private.ElytronMessages.log;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

/**
 * A proxy between an incoming and outgoing (upstream) SASL authentication.  Each received response from the downstream
 * client is proxied to the upstream server, and each received challenge from the upstream server is proxied to the
 * downstream client.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslProxy {

    private static final int ST_FAILED = 0;
    private static final int ST_WAIT_FOR_CHALLENGE = 1;
    private static final int ST_WAIT_FOR_RESPONSE = 2;
    private static final int ST_DONE = 3;

    private static final byte[] EMPTY = new byte[0];

    private final Client client = new Client();
    private final Server server = new Server();

    private final String mechanismName;
    private final boolean responseFirst;

    private final Object lock = new Object();
    private int state;
    private byte[] message = EMPTY;
    private String authorizationID;

    /**
     * Construct a new instance.
     *
     * @param mechanismName the name of the SASL mechanism being proxied
     * @param responseFirst {@code true} if the client should claim that the mechanism is "response first" as opposed to "challenge first"
     */
    public SaslProxy(final String mechanismName, final boolean responseFirst) {
        this.mechanismName = mechanismName;
        this.responseFirst = responseFirst;
        state = responseFirst ? ST_WAIT_FOR_RESPONSE : ST_WAIT_FOR_CHALLENGE;
    }

    final class Client implements SaslClient {

        public String getMechanismName() {
            return mechanismName;
        }

        public boolean hasInitialResponse() {
            return responseFirst;
        }

        public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
            synchronized (lock) {
                for (;;) switch (state) {
                    case ST_FAILED: {
                        throw log.saslProxyAuthenticationFailed();
                    }
                    case ST_DONE: {
                        return null;
                    }
                    case ST_WAIT_FOR_RESPONSE: {
                        try {
                            lock.wait();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            state = ST_FAILED;
                            throw log.saslProxyAuthenticationFailed();
                        }
                        break;
                    }
                    case ST_WAIT_FOR_CHALLENGE: try {
                        return message;
                    } finally {
                        state = ST_WAIT_FOR_RESPONSE;
                        message = challenge;
                        lock.notifyAll();
                    }
                    default: throw new IllegalStateException();
                }
            }
        }

        public boolean isComplete() {
            synchronized (lock) {
                return state == ST_DONE;
            }
        }

        public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
            throw new IllegalStateException("Wrap/unwrap is unsupported");
        }

        public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
            throw new IllegalStateException("Wrap/unwrap is unsupported");
        }

        public Object getNegotiatedProperty(final String propName) {
            return null;
        }

        public void dispose() throws SaslException {
            synchronized (lock) {
                switch (state) {
                    // OK states
                    case ST_FAILED:
                    case ST_DONE: {
                        return;
                    }
                    // work is still in progress
                    case ST_WAIT_FOR_CHALLENGE:
                    case ST_WAIT_FOR_RESPONSE: {
                        state = ST_FAILED;
                        message = null;
                        lock.notifyAll();
                        return;
                    }
                }
            }
        }
    }

    final class Server implements SaslServer {

        public String getMechanismName() {
            return mechanismName;
        }

        public byte[] evaluateResponse(final byte[] response) throws SaslException {
            synchronized (lock) {
                for (;;) switch (state) {
                    case ST_FAILED: {
                        throw log.saslProxyAuthenticationFailed();
                    }
                    case ST_DONE: {
                        return null;
                    }
                    case ST_WAIT_FOR_CHALLENGE: {
                        try {
                            lock.wait();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            state = ST_FAILED;
                            throw log.saslProxyAuthenticationFailed();
                        }
                        break;
                    }
                    case ST_WAIT_FOR_RESPONSE: try {
                        return message;
                    } finally {
                        state = ST_WAIT_FOR_CHALLENGE;
                        message = response;
                        lock.notifyAll();
                    }
                    default: throw new IllegalStateException();
                }
            }
        }

        public boolean isComplete() {
            synchronized (lock) {
                return state == ST_DONE;
            }
        }

        public String getAuthorizationID() {
            synchronized (lock) {
                if (state == ST_DONE) {
                    return authorizationID;
                }
            }
            throw new IllegalStateException();
        }

        public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
            throw new IllegalStateException("Wrap/unwrap is unsupported");
        }

        public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
            throw new IllegalStateException("Wrap/unwrap is unsupported");
        }

        public Object getNegotiatedProperty(final String propName) {
            return null;
        }

        public void dispose() throws SaslException {
            synchronized (lock) {
                switch (state) {
                    // OK states
                    case ST_FAILED:
                    case ST_DONE: {
                        return;
                    }
                    // work is still in progress
                    case ST_WAIT_FOR_CHALLENGE:
                    case ST_WAIT_FOR_RESPONSE: {
                        state = ST_FAILED;
                        message = null;
                        lock.notifyAll();
                        return;
                    }
                }
            }
        }
    }

    /**
     * Get the SASL client.  This is used to communicate with the upstream server.
     *
     * @return the SASL client
     */
    public SaslClient getClient() {
        return client;
    }

    /**
     * Get the SASL server.  This is used to communicate with the downstream client.
     *
     * @return the SASL server
     */
    public SaslServer getServer() {
        return server;
    }

    /**
     * Report that the upstream SASL server has completed authentication.  The given authorization ID is assigned to
     * the SASL server object, however if this property is never queried, then the given authorization ID may be
     * {@code null}.
     *
     * @param authorizationID the authorization ID, or {@code null} if it should not be set
     */
    public void upstreamServerComplete(String authorizationID) {
        synchronized (lock) {
            if (state == ST_DONE) {
                throw new IllegalStateException();
            }
            state = ST_DONE;
            this.authorizationID = authorizationID;
            notifyAll();
        }
    }
}
