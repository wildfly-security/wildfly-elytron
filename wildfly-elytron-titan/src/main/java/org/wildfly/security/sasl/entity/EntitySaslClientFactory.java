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

package org.wildfly.security.sasl.entity;

import static org.wildfly.security.sasl.entity.Entity.*;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Collections;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * The client factory for the ISO/IEC 9798-3 authentication SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(value = SaslClientFactory.class)
public final class EntitySaslClientFactory implements SaslClientFactory {

    public EntitySaslClientFactory() {
        super();
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        String name;
        Signature signature;
        boolean mutual;
        final boolean serverAuth = props != null && Boolean.parseBoolean(String.valueOf(props.get(Sasl.SERVER_AUTH)));
        out: {
            for (String mechanism : mechanisms) {
                mutual = false;
                switch (mechanism) {
                    case SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
                        mutual = true;
                        // Fall through
                    case SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC:
                        if (serverAuth && ! mutual) break;
                        name = mechanism;
                        try {
                            signature = Signature.getInstance(SHA1_WITH_RSA);
                        } catch (NoSuchAlgorithmException e) {
                            break;
                        }
                        break out;
                    case SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1:
                        mutual = true;
                        // Fall through
                    case SaslMechanismInformation.Names.IEC_ISO_9798_U_DSA_SHA1:
                        if (serverAuth && ! mutual) break;
                        name = mechanism;
                        try {
                            signature = Signature.getInstance(SHA1_WITH_DSA);
                        } catch (NoSuchAlgorithmException e) {
                            break;
                        }
                        break out;
                    case SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1:
                        mutual = true;
                        // Fall through
                    case SaslMechanismInformation.Names.IEC_ISO_9798_U_ECDSA_SHA1:
                        if (serverAuth && ! mutual) break;
                        name = mechanism;
                        try {
                            signature = Signature.getInstance(SHA1_WITH_ECDSA);
                        } catch (NoSuchAlgorithmException e) {
                            break;
                        }
                        break out;
                }
            }
            return null;
        }

        final Object rngNameValue = props == null ? null : props.get(WildFlySasl.SECURE_RNG);
        final String rngName = rngNameValue instanceof String ? (String) rngNameValue : null;
        SecureRandom secureRandom = null;
        if (rngName != null) {
            try {
                secureRandom = SecureRandom.getInstance(rngName);
            } catch (NoSuchAlgorithmException ignored) {
            }
        }

        final EntitySaslClient client = new EntitySaslClient(name, mutual, signature, secureRandom, protocol, serverName, cbh, authorizationId);
        client.init();
        return client;
    }

    public String[] getMechanismNames(Map<String, ?> props) {
        if (props == null) props = Collections.emptyMap();
        if (!"true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL)) && "true".equals(props.get(Sasl.SERVER_AUTH))) {
            return new String[] {
                SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC,
                SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1,
                SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1,
            };
        } else {
            return new String[] {
                SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC,
                SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC,
                SaslMechanismInformation.Names.IEC_ISO_9798_U_DSA_SHA1,
                SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1,
                SaslMechanismInformation.Names.IEC_ISO_9798_U_ECDSA_SHA1,
                SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1
            };
        }
    }
}
