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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.callback.AvailableRealmsCallback;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * A {@link SaslServerFactory} which sets the server's available realms using the legacy {@link WildFlySasl#REALM_LIST}
 * property, if specified.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class AvailableRealmsSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    public static final int DEFAULT_DELIMITER = ' ';
    public static final int DEFAULT_ESCAPE_CHARACTER = '\\';

    private final int escapeCharacter;
    private final int[] delims;

    /**
     * Construct a new instance. The delimiter used to separate the realm names in the list of realms is assumed to be
     * {@value #DEFAULT_DELIMITER}. The escape character is assumed to be {@value #DEFAULT_ESCAPE_CHARACTER}.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     */
    public AvailableRealmsSaslServerFactory(final SaslServerFactory delegate) {
        this(delegate, DEFAULT_ESCAPE_CHARACTER, DEFAULT_DELIMITER);
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     * @param escapeCharacter the escape character
     * @param delims the delimiters that separate the realm names in the list of realms
     */
    public AvailableRealmsSaslServerFactory(final SaslServerFactory delegate, final int escapeCharacter, final int... delims) {
        super(delegate);
        this.escapeCharacter = checkNotNullParam("escapeCharacter", escapeCharacter);
        this.delims = checkNotNullParam("delims", delims);
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final String realmList = (String) props.get(WildFlySasl.REALM_LIST);
        if (realmList == null) {
            // The legacy REALM_LIST property wasn't specified
            return delegate.createSaslServer(mechanism, protocol, serverName, props, cbh);
        }
        return delegate.createSaslServer(mechanism, protocol, serverName, props, callbacks -> {
            final ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
            final Iterator<Callback> iterator = list.iterator();
            while (iterator.hasNext()) {
                Callback callback = iterator.next();
                if (callback instanceof AvailableRealmsCallback) {
                    String[] realms = realmListPropertyToArray(realmList, escapeCharacter, delims);
                    ((AvailableRealmsCallback) callback).setRealmNames(realms);
                    iterator.remove();
                }
            }
            if (! list.isEmpty()) {
                cbh.handle(list.toArray(new Callback[list.size()]));
            }
        });
    }


    static String[] realmListPropertyToArray(String realmList) {
        return realmListPropertyToArray(realmList, DEFAULT_ESCAPE_CHARACTER, DEFAULT_DELIMITER);
    }

    static String[] realmListPropertyToArray(String realmList, int escapeCharacter, int... delims) {
        if (realmList == null) {
            return null;
        }
        final int[] escapeCharacterAndDelims = Arrays.copyOf(delims, delims.length + 1);
        escapeCharacterAndDelims[escapeCharacterAndDelims.length - 1] = escapeCharacter;
        final CodePointIterator cpi = CodePointIterator.ofString(realmList);
        final CodePointIterator di = cpi.delimitedBy(escapeCharacterAndDelims);

        final ArrayList<String> realms = new ArrayList<>();
        StringBuilder realm = new StringBuilder();
        while (cpi.hasNext()) {
            if (di.hasNext()) {
                di.drainTo(realm);
            } else {
                if (cpi.peekNext() == escapeCharacter) {
                    cpi.next(); // skip the escape character
                    if (cpi.hasNext()) {
                        realm.append((char) cpi.next());
                    }
                } else {
                    // reached the end of a realm name
                    realms.add(realm.toString());
                    skipDelims(di, cpi, delims);
                    realm = new StringBuilder();
                }
            }
        }
        realms.add(realm.toString());
        return realms.toArray(new String[realms.size()]);
    }

    private static boolean isDelim(int c, int... delims) {
        for (int delim : delims) {
            if (delim == c) {
                return true;
            }
        }
        return false;
    }

    private static void skipDelims(CodePointIterator di, CodePointIterator cpi, int... delims) {
        while ((! di.hasNext()) && cpi.hasNext() && isDelim(cpi.peekNext(), delims)) {
            cpi.next();
        }
    }
}
