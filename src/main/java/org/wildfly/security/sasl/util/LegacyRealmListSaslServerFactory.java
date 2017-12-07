/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.sasl;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * A {@link SaslServerFactory} which uses the {@link AvailableRealmsCallback} to populate the legacy
 * {@link WildFlySasl#REALM_LIST} property, if needed by a mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class LegacyRealmListSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    public static final char DEFAULT_DELIMITER = ' ';
    public static final char DEFAULT_ESCAPE_CHARACTER = '\\';

    private final int escapeCharacter;
    private final int[] delims;

    /**
     * Construct a new instance. The delimiter that should be used to separate the realm names when populating the
     * list of realms is assumed to be {@value #DEFAULT_DELIMITER}. The escape character is assumed to be
     * {@value #DEFAULT_ESCAPE_CHARACTER}.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     */
    public LegacyRealmListSaslServerFactory(final SaslServerFactory delegate) {
        this(delegate, DEFAULT_ESCAPE_CHARACTER, DEFAULT_DELIMITER);
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     * @param escapeCharacter the escape character to use when populating the list of realms
     * @param delims the delimiters that should be used to separate the realm names when populating the list of realms
     */
    public LegacyRealmListSaslServerFactory(final SaslServerFactory delegate, final char escapeCharacter, final String delims) {
        super(delegate);
        checkNotNullParam("escapeCharacter", escapeCharacter);
        checkNotNullParam("delims", delims);
        this.escapeCharacter = escapeCharacter;
        this.delims = delims.chars().toArray();
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     * @param escapeCharacter the escape character to use when populating the list of realms
     * @param delims the delimiters that should be used to separate the realm names when populating the list of realms
     */
    public LegacyRealmListSaslServerFactory(final SaslServerFactory delegate, final char escapeCharacter, final int... delims) {
        super(delegate);
        this.escapeCharacter = checkNotNullParam("escapeCharacter", escapeCharacter);
        this.delims = checkNotNullParam("delims", delims);
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        String[] realms = null;
        final AvailableRealmsCallback availableRealmsCallback = new AvailableRealmsCallback();
        try {
            cbh.handle(new Callback[] { availableRealmsCallback });
            realms = availableRealmsCallback.getRealmNames();
        } catch (UnsupportedCallbackException ignored) {
        } catch (SaslException e) {
            throw e;
        } catch (IOException e) {
            throw sasl.mechCallbackHandlerFailedForUnknownReason(e).toSaslException();
        }
        if (realms == null) {
            realms = new String[] { serverName };
        }
        final String realmList = arrayToRealmListProperty(realms, escapeCharacter, delims);
        final Map<String, Object> newProps = new HashMap<String, Object>(props) {
            public Object get(Object key) {
                Object value = super.get(key);
                if (key.equals(WildFlySasl.REALM_LIST) && (value == null)) {
                    value = realmList;
                    put(WildFlySasl.REALM_LIST, value);
                }
                return value;
            }
        };
        return delegate.createSaslServer(mechanism, protocol, serverName, newProps, cbh);
    }

    static String arrayToRealmListProperty(String[] realms) {
        return arrayToRealmListProperty(realms, DEFAULT_ESCAPE_CHARACTER, DEFAULT_DELIMITER);
    }

    static String arrayToRealmListProperty(String[] realms, int escapeCharacter, int... delims) {
        if (realms == null) {
            return null;
        }
        final int[] escapeCharacterAndDelims = Arrays.copyOf(delims, delims.length + 1);
        escapeCharacterAndDelims[escapeCharacterAndDelims.length - 1] = escapeCharacter;
        StringBuilder realmList = new StringBuilder();
        for (int i = 0; i < realms.length; i++) {
            if (i != 0) {
                addDelims(realmList, delims);
            }
            CodePointIterator cpi = CodePointIterator.ofString(realms[i]);
            CodePointIterator di = cpi.delimitedBy(escapeCharacterAndDelims);
            while (cpi.hasNext()) {
                if (di.hasNext()) {
                    di.drainTo(realmList);
                } else {
                    realmList.append((char) escapeCharacter); // escape the delimiter or escape character
                    realmList.append((char) cpi.next());
                }
            }
        }
        return realmList.toString();
    }

    private static void addDelims(StringBuilder realmList, int... delims) {
        for (int delim : delims) {
            realmList.append((char) delim);
        }
    }
}
