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
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * The server factory for the ISO/IEC 9798-3 authentication SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(value = SaslServerFactory.class)
public final class EntitySaslServerFactory implements SaslServerFactory {

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        Signature signature;
        boolean mutual = false;
        final Object serverAuthValue = props.get(Sasl.SERVER_AUTH);
        final boolean serverAuth = serverAuthValue instanceof String ? "true".equals((String) serverAuthValue) : false;
        switch (mechanism) {
            case Entity.ENTITY_MUTUAL_RSA_SHA1_ENC:
                mutual = true;
                // Fall through
            case Entity.ENTITY_UNILATERAL_RSA_SHA1_ENC:
                if (serverAuth != mutual) return null;
                try {
                    signature = Signature.getInstance(SHA1_WITH_RSA);
                } catch (NoSuchAlgorithmException e) {
                    return null;
                }
                break;
            case Entity.ENTITY_MUTUAL_DSA_SHA1:
                mutual = true;
                // Fall through
            case Entity.ENTITY_UNILATERAL_DSA_SHA1:
                if (serverAuth != mutual) return null;
                try {
                    signature = Signature.getInstance(SHA1_WITH_DSA);
                } catch (NoSuchAlgorithmException e) {
                    return null;
                }
                break;
            case Entity.ENTITY_MUTUAL_ECDSA_SHA1:
                mutual = true;
                // Fall through
            case Entity.ENTITY_UNILATERAL_ECDSA_SHA1:
                if (serverAuth != mutual) return null;
                try {
                    signature = Signature.getInstance(SHA1_WITH_ECDSA);
                } catch (NoSuchAlgorithmException e) {
                    return null;
                }
                break;
            default: {
                return null;
            }
        }
        final Object rngNameValue = props.get(WildFlySasl.SECURE_RNG);
        final String rngName = rngNameValue instanceof String ? (String) rngNameValue : null;
        SecureRandom secureRandom = null;
        if (rngName != null) {
            try {
                secureRandom = SecureRandom.getInstance(rngName);
            } catch (NoSuchAlgorithmException ignored) {
            }
        }
        final EntitySaslServer server = new EntitySaslServer(mechanism, protocol, serverName, cbh, props, signature, secureRandom);
        server.init();
        return server;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        if (!"true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL)) && "true".equals(props.get(Sasl.SERVER_AUTH))) {
            return new String[] {
                Entity.ENTITY_MUTUAL_RSA_SHA1_ENC,
                Entity.ENTITY_MUTUAL_DSA_SHA1,
                Entity.ENTITY_MUTUAL_ECDSA_SHA1,
            };
        } else if (!"true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL)) && "false".equals(props.get(Sasl.SERVER_AUTH))) {
            return new String[] {
                Entity.ENTITY_UNILATERAL_RSA_SHA1_ENC,
                Entity.ENTITY_UNILATERAL_DSA_SHA1,
                Entity.ENTITY_UNILATERAL_ECDSA_SHA1
            };
        } else {
            return new String[] {
                Entity.ENTITY_UNILATERAL_RSA_SHA1_ENC,
                Entity.ENTITY_MUTUAL_RSA_SHA1_ENC,
                Entity.ENTITY_UNILATERAL_DSA_SHA1,
                Entity.ENTITY_MUTUAL_DSA_SHA1,
                Entity.ENTITY_UNILATERAL_ECDSA_SHA1,
                Entity.ENTITY_MUTUAL_ECDSA_SHA1
            };
        }
    }
}
