/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.gs2;

import static org.wildfly.security.sasl.gs2.Gs2.*;

import java.util.ArrayList;

import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class Gs2Util {

    public static final int TOKEN_HEADER_TAG = 0x60;

    /**
     * Get the array of supported SASL mechanism names that corresponds to the given array of GSS-API
     * mechanism object identifiers.
     *
     * @param mechanismOids the array of GSS-API mechanism object identifiers
     * @return the array of supported SASL mechanism names that corresponds to the given array of GSS-API
     * mechanism object identifiers
     * @throws GSSException if an error occurs while mapping the GSS-API object identifiers to SASL names
     */
    public static String[] getSupportedSaslNamesForMechanisms(Oid[] mechanismOids) throws GSSException {
        if (mechanismOids == null) {
            return WildFlySasl.NO_NAMES;
        }
        ArrayList<String> saslNames = new ArrayList<String>();
        ArrayList<String> nonPlusSaslNames = new ArrayList<>();
        String name;
        for (int i = 0; i < mechanismOids.length; i++) {
            name = getSaslNameForMechanism(mechanismOids[i]);
            // Note: SPNEGO must not be used as a GS2 mechanism (see https://tools.ietf.org/html/rfc5801#section-14.3).
            // Future mechanisms that negotiate other mechanisms would need to be forbidden as well.
            if (! name.equals(SPNEGO)) {
                nonPlusSaslNames.add(name);
                saslNames.add(name + PLUS_SUFFIX);
            }
        }
        saslNames.addAll(nonPlusSaslNames);
        return saslNames.toArray(new String[saslNames.size()]);
    }

    /**
     * Determine if the given mechanism name is among the given array of mechanism names.
     *
     * @param name the mechanism name
     * @param mechanisms the array of mechanism names
     * @return {@code true} if the given name is among the given mechanism names and
     * {@code false} otherwise
     */
    public static boolean isIncluded(String name, String[] mechanisms) {
        if ((name == null) || (mechanisms == null)) {
            return false;
        }
        for (String mechanism : mechanisms) {
            if (name.equals(mechanism)) {
                return true;
            }
        }
        return false;
    }

    public static String[] getPlusMechanisms(String[] mechanisms) {
        ArrayList<String> plusMechanisms = new ArrayList<String>();
        for (String mechanism : mechanisms) {
            if (mechanism.endsWith(PLUS_SUFFIX)) {
                plusMechanisms.add(mechanism);
            }
        }
        return plusMechanisms.toArray(new String[plusMechanisms.size()]);
    }

    /**
     * Create a {@code ChannelBinding} whose application data field is set to the given GS2 header,
     * concatenated with, when a gs2-cb-flag of "p" is used, the given channel binding data.
     *
     * @param header the GS2 header, excluding the initial gs2-nonstd-flag
     * @param gs2CbFlagPUsed whether or not a gs2-cb-flag of "p" is used
     * @param bindingData the channel binding data
     * @return the {@code ChannelBinding}
     */
    public static ChannelBinding createChannelBinding(byte[] header, boolean gs2CbFlagPUsed, byte[] bindingData) {
        ByteStringBuilder appData = new ByteStringBuilder(header);
        if (gs2CbFlagPUsed) {
            appData.append(bindingData);
        }
        return new ChannelBinding(appData.toArray());
    }
}
