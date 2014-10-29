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

package org.wildfly.security.sasl.scram;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import javax.crypto.Mac;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(value = SaslClientFactory.class)
public final class ScramSaslClientFactory implements SaslClientFactory {

    public ScramSaslClientFactory() {
        super();
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        String name;
        boolean plus = false;
        final ChannelBindingCallback callback = new ChannelBindingCallback();
        try {
            cbh.handle(new Callback[] { callback });
        } catch (SaslException e) {
            throw e;
        } catch (IOException e) {
            throw new SaslException("Failed to determine channel binding status", e);
        } catch (UnsupportedCallbackException e) {
            // ignored
        }
        final String bindingType = callback.getBindingType();
        final byte[] bindingData = callback.getBindingData();
        boolean bindingOk = bindingType != null && bindingData != null;
        boolean bindingRequired = "true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED));
        MessageDigest messageDigest;
        Mac mac;
        out: {
            for (String mechanism : mechanisms) {
                switch (mechanism) {
                    case Scram.SCRAM_SHA_1_PLUS:
                        if (! bindingOk) break;
                        plus = true;
                        // fall thru
                    case Scram.SCRAM_SHA_1:
                        if (bindingRequired && ! plus) break;
                        name = mechanism;
                        try {
                            messageDigest = MessageDigest.getInstance("SHA-1");
                            mac = Mac.getInstance("HmacSHA1");
                        } catch (NoSuchAlgorithmException e) {
                            break;
                        }
                        break out;
                    case Scram.SCRAM_SHA_256_PLUS:
                        if (! bindingOk) break;
                        plus = true;
                        // fall thru
                    case Scram.SCRAM_SHA_256:
                        if (bindingRequired && ! plus) break;
                        name = mechanism;
                        try {
                            messageDigest = MessageDigest.getInstance("SHA-256");
                            mac = Mac.getInstance("HmacSHA256");
                        } catch (NoSuchAlgorithmException e) {
                            break;
                        }
                        break out;
                    case Scram.SCRAM_SHA_384_PLUS:
                        if (! bindingOk) break;
                        plus = true;
                        // fall thru
                    case Scram.SCRAM_SHA_384:
                        if (bindingRequired && ! plus) break;
                        name = mechanism;
                        try {
                            messageDigest = MessageDigest.getInstance("SHA-384");
                            mac = Mac.getInstance("HmacSHA384");
                        } catch (NoSuchAlgorithmException e) {
                            break;
                        }
                        break out;
                    case Scram.SCRAM_SHA_512_PLUS:
                        if (! bindingOk) break;
                        plus = true;
                        // fall thru
                    case Scram.SCRAM_SHA_512:
                        if (bindingRequired && ! plus) break;
                        name = mechanism;
                        try {
                            messageDigest = MessageDigest.getInstance("SHA-512");
                            mac = Mac.getInstance("HmacSHA512");
                        } catch (NoSuchAlgorithmException e) {
                            break;
                        }
                        break out;
                }
            }
            return null;
        }
        final Object propVal = props.get(WildFlySasl.SECURE_RNG);
        final String rngName = propVal instanceof String ? (String) propVal : null;
        SecureRandom secureRandom = null;
        if (rngName != null) {
            try {
                secureRandom = SecureRandom.getInstance(rngName);
            } catch (NoSuchAlgorithmException ignored) {
            }
        }
        final ScramSaslClient client = new ScramSaslClient(name, messageDigest, mac, secureRandom, protocol, serverName, cbh, authorizationId, props, plus, bindingType, bindingData);
        client.init();
        return client;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        if ("true".equals(props.get(WildFlySasl.CHANNEL_BINDING_REQUIRED))) {
            return new String[] {
                Scram.SCRAM_SHA_1_PLUS,
                Scram.SCRAM_SHA_256_PLUS,
                Scram.SCRAM_SHA_384_PLUS,
                Scram.SCRAM_SHA_512_PLUS,
            };
        } else {
            return new String[] {
                Scram.SCRAM_SHA_1,
                Scram.SCRAM_SHA_1_PLUS,
                Scram.SCRAM_SHA_256,
                Scram.SCRAM_SHA_256_PLUS,
                Scram.SCRAM_SHA_384,
                Scram.SCRAM_SHA_384_PLUS,
                Scram.SCRAM_SHA_512,
                Scram.SCRAM_SHA_512_PLUS,
            };
        }
    }
}
