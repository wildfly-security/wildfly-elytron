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

package org.jboss.sasl.util;

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
public abstract class AbstractSaslParticipant {

    /**
     * An empty byte array.
     */
    public static final byte[] NO_BYTES = new byte[0];

    private final SaslStateContext context = new SaslStateContext() {
        public void setNegotiationState(final SaslState newState) {
            state = newState;
        }

        public void negotiationComplete() {
            state = SaslState.COMPLETE;
        }
    };

    private final String mechanismName;
    private final CallbackHandler callbackHandler;
    private final String protocol;
    private final String serverName;

    private SaslState state;
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
        } catch (SaslException e) {
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
     * Get the current negotiation state context.
     *
     * @return the context
     */
    public SaslStateContext getContext() {
        return context;
    }

    byte[] evaluateMessage(final byte[] message) throws SaslException {
        boolean ok = true;
        try {
            byte[] result = state.evaluateMessage(context, message);
            ok = true;
            return result;
        } finally {
            if (! ok) {
                state = SaslState.FAILED;
            }
        }
    }

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
        return wrapper.unwrap(incoming, offset, len);
    }

    /**
     * Determine whether the authentication exchange has completed.
     *
     * @return {@code true} if the exchange has completed
     */
    public boolean isComplete() {
        return state == SaslState.COMPLETE;
    }

    /**
     * Get a property negotiated between this participant and the other.
     *
     * @param propName the property name
     * @return the property value or {@code null} if not defined
     */
    @SuppressWarnings("unused")
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
