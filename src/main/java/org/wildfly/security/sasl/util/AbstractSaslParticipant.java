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

package org.wildfly.security.sasl.util;

import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

/**
 * A common base class for SASL participants.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractSaslParticipant implements SaslWrapper {

    /**
     * An empty byte array.
     */
    public static final byte[] NO_BYTES = new byte[0];

    /**
     * The SASL negotiation failure state.
     */
    public static final int FAILED_STATE = -1;

    /**
     * The SASL negotiation completed state.
     */
    public static final int COMPLETE_STATE = 0;

    private final String mechanismName;
    private final CallbackHandler callbackHandler;
    private final String protocol;
    private final String serverName;

    private int state = -1;
    private SaslWrapper wrapper;

    /**
     * Construct a new instance.
     *
     * @param mechanismName the name of the defined mechanism
     * @param protocol the protocol
     * @param serverName the server name
     * @param callbackHandler the callback handler
     */
    protected AbstractSaslParticipant(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
        this.mechanismName = mechanismName;
        this.protocol = protocol;
        this.serverName = serverName;
    }

    /**
     * Handle callbacks, wrapping exceptions as needed (including unsupported callbacks).
     *
     * @param callbacks the callbacks to handle
     * @throws SaslException if a callback failed
     */
    protected void handleCallbacks(Callback... callbacks) throws SaslException {
        try {
            tryHandleCallbacks(callbacks);
        } catch (UnsupportedCallbackException e) {
            throw new SaslException("Callback handler cannot support callback " + e.getCallback().getClass(), e);
        }
    }

    /**
     * Handle callbacks, wrapping exceptions as needed.
     *
     * @param callbacks the callbacks to handle
     * @throws SaslException if a callback failed
     * @throws UnsupportedCallbackException if a callback isn't supported
     */
    protected void tryHandleCallbacks(Callback... callbacks) throws SaslException, UnsupportedCallbackException {
        try {
            callbackHandler.handle(callbacks);
        } catch (SaslException | UnsupportedCallbackException e) {
            throw e;
        } catch (Throwable t) {
            throw new SaslException("Callback handler invocation failed", t);
        }
    }

    public void init() {}

    /**
     * Get the name of this mechanism.
     *
     * @return the mechanism name
     */
    public String getMechanismName() {
        return mechanismName;
    }

    /**
     * Get the protocol name.
     *
     * @return the protocol name
     */
    protected String getProtocol() {
        return protocol;
    }

    /**
     * Get the server name.
     *
     * @return the server name
     */
    protected String getServerName() {
        return serverName;
    }

    /**
     * Get the configured authentication callback handler.
     *
     * @return the callback handler
     */
    protected CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    /**
     * Get the current configured SASL wrapper, if any.
     *
     * @return the SASL wrapper, or {@code null} if none is configured
     */
    protected SaslWrapper getWrapper() {
        return wrapper;
    }

    /**
     * Set the state to use for the next incoming message.
     *
     * @param newState the new state
     */
    public void setNegotiationState(final int newState) {
        state = newState;
    }

    /**
     * Indicate that negotiation is complete.  To re-initiate negotiation, call {@link #setNegotiationState(int)}.
     */
    public void negotiationComplete() {
        state = COMPLETE_STATE;
    }

    protected byte[] evaluateMessage(final byte[] message) throws SaslException {
        boolean ok = false;
        try {
            if (state == COMPLETE_STATE) {
                throw new SaslException("SASL negotiation already complete");
            } else if (state == FAILED_STATE) {
                throw new SaslException("SASL negotiation failed");
            }
            byte[] result = evaluateMessage(state, message);
            ok = true;
            return result;
        } finally {
            if (! ok) {
                state = FAILED_STATE;
            }
        }
    }

    protected abstract byte[] evaluateMessage(int state, final byte[] message) throws SaslException;

    /**
     * Set the current configured SASL wrapper, if any.
     *
     * @param wrapper the SASL wrapper, or {@code null} to disable wrapping
     */
    protected void setWrapper(final SaslWrapper wrapper) {
        this.wrapper = wrapper;
    }

    /**
     * Wraps a byte array to be sent to the other participant.
     *
     * @param outgoing a non-{@code null} byte array containing the bytes to encode
     * @param offset the first byte to encode
     * @param len the number of bytes to use
     * @return A non-{@code null} byte array containing the encoded bytes
     * @exception SaslException if wrapping fails
     * @exception IllegalStateException if wrapping is not configured
     */
    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        SaslWrapper wrapper = this.wrapper;
        if (wrapper == null) {
            throw new IllegalStateException("Wrapping is not configured");
        }
        if(len == 0) {
            return NO_BYTES;
        }
        return wrapper.wrap(outgoing, offset, len);
    }

    /**
     * Unwraps a byte array received from the other participant.
     *
     * @param incoming a non-{@code null} byte array containing the bytes to decode
     * @param offset the first byte to decode
     * @param len the number of bytes to use
     * @return A non-{@code null} byte array containing the decoded bytes
     * @exception SaslException if wrapping fails
     * @exception IllegalStateException if wrapping is not configured
     */
    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        SaslWrapper wrapper = this.wrapper;
        if (wrapper == null) {
            throw new IllegalStateException("Wrapping is not configured");
        }
        if(len == 0) {
            return NO_BYTES;
        }
        return wrapper.unwrap(incoming, offset, len);
    }

    /**
     * Determine whether the authentication exchange has completed.
     *
     * @return {@code true} if the exchange has completed
     */
    public boolean isComplete() {
        return state == COMPLETE_STATE;
    }

    /**
     * A convenience method to throw a {@link IllegalStateException} is authentication is not yet complete.
     *
     * To be called by methods that must only be called after authentication is complete.
     */
    protected void assertComplete() {
        if (isComplete() == false) {
            throw new IllegalStateException("Authentication is not yet complete.");
        }
    }

    /**
     * Get a property negotiated between this participant and the other.
     *
     * @param propName the property name
     * @return the property value or {@code null} if not defined
     */
    public Object getNegotiatedProperty(final String propName) {
        return null;
    }

    /**
     * Get a string property value from the given map.
     *
     * @param map the property map
     * @param key the property
     * @param defaultVal the value to return if the key is not in the map
     * @return the value
     */
    public String getStringProperty(Map<String, ?> map, String key, String defaultVal) {
        final Object val = map.get(key);
        if (val == null) {
            return defaultVal;
        } else {
            return String.valueOf(val);
        }
    }

    /**
     * Get a string property value from the given map.
     *
     * @param map the property map
     * @param key the property
     * @param defaultVal the value to return if the key is not in the map
     * @return the value
     */
    public int getIntProperty(Map<String, ?> map, String key, int defaultVal) {
        final Object val = map.get(key);
        if (val == null) {
            return defaultVal;
        } else {
            return Integer.parseInt(val.toString());
        }
    }



    /**
     * Dispose of this participant.
     *
     * @throws SaslException if disposal failed
     */
    public void dispose() throws SaslException {
    }
}
