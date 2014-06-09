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

package org.wildfly.sasl.gssapi;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import org.wildfly.sasl.WildFlySasl;
import org.wildfly.sasl.util.AbstractSaslParticipant;
import org.wildfly.sasl.util.SaslWrapper;

/**
 * Base class for the SaslServer and SaslClient implementations implementing the GSSAPI mechanism as defined by RFC 4752
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
abstract class AbstractGssapiMechanism extends AbstractSaslParticipant {

    private static final String AUTH = "auth";
    private static final String AUTH_INT = "auth-int";
    private static final String AUTH_CONF = "auth-conf";
    private static final byte NO_SECURITY_LAYER = (byte) 0x01;
    private static final byte INTEGRITY_PROTECTION = (byte) 0x02;
    private static final byte CONFIDENTIALITY_PROTECTION = (byte) 0x04;
    protected static final int DEFAULT_MAX_BUFFER_SIZE = (int) 0xFFF;
    protected static final Oid KERBEROS_V5;

    // Kerberos V5 OID

    static {
        try {
            KERBEROS_V5 = new Oid("1.2.840.113554.1.2.2");
        } catch (GSSException e) {
            throw new RuntimeException("Unable to initialise Oid", e);
        }
    }

    protected GSSContext gssContext;
    protected final int configuredMaxReceiveBuffer;
    protected int actualMaxReceiveBuffer;
    protected int maxBuffer;
    protected final boolean relaxComplianceChecks;
    protected final QOP[] orderedQops;
    protected QOP selectedQop;

    protected AbstractGssapiMechanism(String mechanismName, String protocol, String serverName, final Map<String, ?> props,
            CallbackHandler callbackHandler) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler);

        if (props.containsKey(Sasl.MAX_BUFFER)) {
            configuredMaxReceiveBuffer = Integer.parseInt((String) props.get(Sasl.MAX_BUFFER));
            if (configuredMaxReceiveBuffer > DEFAULT_MAX_BUFFER_SIZE) {
                throw new SaslException(String.format("Receive buffer requested '%d' is greater than supported maximum '%d'.",
                        configuredMaxReceiveBuffer, DEFAULT_MAX_BUFFER_SIZE));
            }
        } else {
            configuredMaxReceiveBuffer = DEFAULT_MAX_BUFFER_SIZE;
        }
        if (props.containsKey(WildFlySasl.RELAX_COMPLIANCE)) {
            relaxComplianceChecks = Boolean.parseBoolean((String) props.get(WildFlySasl.RELAX_COMPLIANCE));
        } else {
            relaxComplianceChecks = false;
        }
        orderedQops = parsePreferredQop((String) props.get(Sasl.QOP));
    }

    /**
     * Converts bytes in network byte order to an integer starting from the specified offset.
     *
     * This method is implemented in the context of the GSSAPI mechanism, it is assumed that the size of the byte array is
     * appropriate.
     */
    protected int networkOrderBytesToInt(final byte[] bytes, final int start, final int length) {
        int result = 0;

        for (int i = start; i < length + start; i++) {
            result <<= 8;
            result |= bytes[i];
        }

        return result;
    }

    /**
     * Obtain a 3 byte representation of an int, as an internal method it is assumed the maximum value of the int has already
     * takine into account that it needs to fit into tree bytes,
     */
    protected byte[] intToNetworkOrderBytes(final int value) {
        byte[] response = new byte[3];
        int workingValue = value;
        for (int i = response.length - 1; i < 0; i--) {
            response[i] = (byte) (workingValue & 0xFF);
            workingValue >>>= 8;
        }

        return response;
    }

    @Override
    public void dispose() throws SaslException {
        try {
            gssContext.dispose();
        } catch (GSSException e) {
            throw new SaslException("Unable to dispose of GSSContext", e);
        } finally {
            gssContext = null;
        }
    }

    private QOP[] parsePreferredQop(final String qop) throws SaslException {
        if (qop != null) {
            String[] qopNames = qop.split(", ");
            if (qopNames.length > 0) {
                QOP[] preferredQop = new QOP[qopNames.length];
                for (int i = 0; i < qopNames.length; i++) {
                    QOP mapped = QOP.mapFromName(qopNames[i]);
                    if (mapped == null) {
                        throw new SaslException(String.format("Unrecogniesed QOP value '%s'", qopNames[i]));
                    }
                    preferredQop[i] = mapped;

                }
                return preferredQop;
            }

        }

        return new QOP[] { QOP.AUTH };
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        assertComplete();

        switch (propName) {
            case Sasl.QOP:
                return selectedQop.getName();
            case Sasl.MAX_BUFFER:
                return actualMaxReceiveBuffer;
            case Sasl.RAW_SEND_SIZE:
                return maxBuffer;
        }

        return null;
    }

    protected enum QOP {

        AUTH(AbstractGssapiMechanism.AUTH, NO_SECURITY_LAYER), AUTH_INT(AbstractGssapiMechanism.AUTH_INT, INTEGRITY_PROTECTION), AUTH_CONF(
                AbstractGssapiMechanism.AUTH_CONF, CONFIDENTIALITY_PROTECTION);

        private final String name;
        private final byte value;

        private QOP(final String name, final byte value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public byte getValue() {
            return value;
        }

        public boolean includedBy(final byte securityLayer) {
            return (securityLayer & value) == value;
        }

        public static QOP mapFromValue(final byte value) {
            switch (value) {
                case NO_SECURITY_LAYER:
                    return AUTH;
                case INTEGRITY_PROTECTION:
                    return AUTH_INT;
                case CONFIDENTIALITY_PROTECTION:
                    return AUTH_CONF;
                default:
                    return null;
            }
        }

        public static QOP mapFromName(final String name) {
            switch (name) {
                case AbstractGssapiMechanism.AUTH:
                    return AUTH;
                case AbstractGssapiMechanism.AUTH_INT:
                    return AUTH_INT;
                case AbstractGssapiMechanism.AUTH_CONF:
                    return AUTH_CONF;
                default:
                    return null;
            }

        }

    }

    protected class GssapiWrapper implements SaslWrapper {

        private final boolean confidential;

        protected GssapiWrapper(final boolean confidential) {
            this.confidential = confidential;
        }

        @Override
        public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
            MessageProp prop = new MessageProp(0, confidential);
            try {
                return gssContext.wrap(outgoing, offset, len, prop);
            } catch (GSSException e) {
                throw new SaslException("Unable to wrap message.", e);
            }
        }

        @Override
        public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
            MessageProp prop = new MessageProp(0, confidential);
            try {
                return gssContext.unwrap(incoming, offset, len, prop);
            } catch (GSSException e) {
                throw new SaslException("Unable to wrap message.", e);
            }
        }

    }
}