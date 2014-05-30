/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.sasl;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslProxy {
    private static final int S_WAITING_FOR_CLIENT   = 0;
    private static final int S_HAVE_RESPONSE        = 1;
    private static final int S_WAITING_FOR_SERVER   = 2;
    private static final int S_HAVE_CHALLENGE       = 3;
    private static final int S_COMPLETE             = 4;
    private static final int S_INTERRUPTED          = 5;
    private static final int S_FAILED               = 6;

    private final String mechanismName;
    private final String authorizationId;
    private final Object lock = new Object();
    private int state;
    private byte[] buffer;

    public SaslProxy(final String mechanismName, final String authorizationId) {
        this.mechanismName = mechanismName;
        this.authorizationId = authorizationId;
    }

    private final SaslClient client = new SaslClient() {
        public String getMechanismName() {
            return mechanismName;
        }

        public boolean hasInitialResponse() {
            // sure, why not?
            return true;
        }

        public byte[] evaluateChallenge(final byte[] challengeFromServer) throws SaslException {
            return evaluateMessage(challengeFromServer, true);
        }

        public boolean isComplete() {
            return SaslProxy.this.isComplete();
        }

        public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
            throw new IllegalStateException();
        }

        public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
            throw new IllegalStateException();
        }

        public Object getNegotiatedProperty(final String propName) {
            return null;
        }

        public void dispose() throws SaslException {
            SaslProxy.this.dispose();
        }
    };
    private final SaslServer server = new SaslServer() {
        public String getMechanismName() {
            return mechanismName;
        }

        public byte[] evaluateResponse(final byte[] responseFromClient) throws SaslException {
            return evaluateMessage(responseFromClient, false);
        }

        public boolean isComplete() {
            return SaslProxy.this.isComplete();
        }

        public String getAuthorizationID() {
            return authorizationId;
        }

        public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
            throw new IllegalStateException();
        }

        public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
            throw new IllegalStateException();
        }

        public Object getNegotiatedProperty(final String propName) {
            return null;
        }

        public void dispose() throws SaslException {
            SaslProxy.this.dispose();
        }
    };

    byte[] evaluateMessage(final byte[] inboundMessage, final boolean fromServer) throws SaslException {
        int state;
        final int waitIn, waitOut, haveMsg;
        if (fromServer) {
            // from server to client
            waitIn = S_WAITING_FOR_CLIENT;
            waitOut = S_WAITING_FOR_SERVER;
            haveMsg = S_HAVE_RESPONSE;
        } else {
            // from client to server
            waitIn = S_WAITING_FOR_SERVER;
            waitOut = S_WAITING_FOR_CLIENT;
            haveMsg = S_HAVE_CHALLENGE;
        }
        byte[] outboundMessage;
        synchronized (lock) {
            state = this.state;
            while (state == waitIn) {
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    this.state = S_INTERRUPTED;
                    buffer = null;
                    lock.notifyAll();
                    throw new SaslAuthenticationInterruptedException();
                }
                state = this.state;
            }
            if (state == S_INTERRUPTED) {
                throw new SaslAuthenticationInterruptedException();
            } else if (state == S_COMPLETE) {
                return null;
            } else if (state == S_FAILED) {
                throw new SaslException("Unspecified failure");
            } else if (state == haveMsg) {

            } else {
                throw new IllegalStateException();
            }

            buffer = inboundMessage;
            this.state = waitOut;
            lock.notify();
            do {
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    this.state = S_INTERRUPTED;
                    buffer = null;
                    lock.notifyAll();
                    throw new SaslAuthenticationInterruptedException();
                }
                state = this.state;
            } while (state == waitOut);
            if (state == waitIn) {
                outboundMessage = buffer; // may be {@code null}
                buffer = null;
            } else {
                throw new IllegalStateException();
            }
        }
        return outboundMessage;
    }

    boolean isComplete() {
        final int state;
        synchronized (lock) {
            state = this.state;
        }
        return state == S_COMPLETE || state == S_FAILED || state == S_INTERRUPTED;
    }

    void dispose() {
        int state = this.state;
        synchronized (lock) {
            if (state == S_COMPLETE || state == S_FAILED || state == S_INTERRUPTED) {
                return;
            }
            buffer = null;
            this.state = S_INTERRUPTED;
            lock.notifyAll();
        }
    }

    /**
     * Get the SASL client which is used to communicate with the upstream server.
     *
     * @return the SASL client
     */
    public SaslClient getClient() {
        return client;
    }

    /**
     * Get the SASL server which is used to communicate with the downstream client.
     *
     * @return the SASL server
     */
    public SaslServer getServer() {
        return server;
    }

    /**
     * Indicate that the authentication to the upstream server has completed successfully.
     */
    public void serverAuthenticationFinished() {

    }

    /**
     * Indicate that the authentication to the upstream server has failed.
     */
    public void serverAuthenticationFailed() {

    }

    public void clientAuthenticationFailed() {

    }
}
