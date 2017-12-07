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

package org.wildfly.security.sasl.otp;

import static org.wildfly.security.sasl.otp.OTPUtil.*;
import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.kohsuke.MetaInfServices;
import org.wildfly.common.Assert;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * The client factory for the OTP SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(value = SaslClientFactory.class)
public final class OTPSaslClientFactory implements SaslClientFactory {

    private final Supplier<Provider[]> providers;

    public OTPSaslClientFactory() {
        providers = INSTALLED_PROVIDERS;
    }

    public OTPSaslClientFactory(final Provider provider) {
        providers = () -> new Provider[] { provider };
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        Assert.checkNotNullParam("cbh", cbh);
        if (props == null) props = Collections.emptyMap();
        if (OTP.isMatched(props, false)) {
            for (String mechanism : mechanisms) {
                if (SaslMechanismInformation.Names.OTP.equals(mechanism)) {
                    final Object rngNameValue = props.get(WildFlySasl.SECURE_RNG);
                    final String rngName = rngNameValue instanceof String ? (String) rngNameValue : null;
                    SecureRandom secureRandom = null;
                    if (rngName != null) {
                        try {
                            secureRandom = SecureRandom.getInstance(rngName);
                        } catch (NoSuchAlgorithmException ignored) {
                        }
                    }
                    final String alternateDictionaryProperty = (String)props.get(WildFlySasl.OTP_ALTERNATE_DICTIONARY);
                    String[] alternateDictionary = null;
                    if ((alternateDictionaryProperty != null) && (! alternateDictionaryProperty.isEmpty())) {
                        alternateDictionary = dictionaryPropertyToArray(alternateDictionaryProperty);
                        validateAlternateDictionary(alternateDictionary);
                    }
                    final OTPSaslClient client = new OTPSaslClient(mechanism, secureRandom, alternateDictionary, protocol, serverName, cbh, authorizationId, providers);
                    client.init();
                    return client;
                }
            }
        }
        return null;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return OTP.isMatched(props, true) ? new String[] { SaslMechanismInformation.Names.OTP } : WildFlySasl.NO_NAMES;
    }

    /**
     * Construct the value of the {@code OTP_ALTERNATE_DICTIONARY} property from an array of words.
     *
     * @param dictionaryArray the array of words in the alternate dictionary
     * @return the alternate dictionary as a string, where each word is separated by a
     * space character
     */
    public static String dictionaryArrayToProperty(String[] dictionaryArray){
        StringBuilder dictionary = new StringBuilder();
        for (int i = 0; i < dictionaryArray.length; i++){
            if (i != 0) {
                dictionary.append(OTP.DICTIONARY_DELIMITER);
            }
            dictionary.append(dictionaryArray[i]);
        }
        return dictionary.toString();
    }

    static String[] dictionaryPropertyToArray(String property) throws SaslException {
        String[] dictionary = new String[OTP.DICTIONARY_SIZE];
        CodePointIterator cpi = CodePointIterator.ofString(property);
        CodePointIterator di = cpi.delimitedBy(OTP.DICTIONARY_DELIMITER);
        for (int i = 0; i < dictionary.length; i++) {
            dictionary[i] = di.drainToString();
            skipDelims(di, cpi, OTP.DICTIONARY_DELIMITER);
        }
        return dictionary;
    }
}
