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

package org.wildfly.security.sasl.external;

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
import org.wildfly.security.util._private.Arrays2;

/**
 * Implementation of the SASL {@code EXTERNAL} client mechanism.  See <a href="https://tools.ietf.org/html/rfc4422#appendix-A">RFC 4422
 * appendix A</a> for more information about the {@code EXTERNAL} mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(value = SaslClientFactory.class)
public final class ExternalSaslClientFactory implements SaslClientFactory {

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        if (getMechanismNames(props).length != 0) {
            for (String mechanism : mechanisms) {
                if (SaslMechanismInformation.Names.EXTERNAL.equals(mechanism)) {
                    return new ExternalSaslClient(authorizationId);
                }
            }
        }
        return null;
    }

    public String[] getMechanismNames(Map<String, ?> props) {
        if (props == null) props = Collections.emptyMap();
        if ("true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL))) {
            return Arrays2.of(SaslMechanismInformation.Names.EXTERNAL);
        }
        if ("true".equals(props.get(Sasl.POLICY_NOACTIVE))) {
            return WildFlySasl.NO_NAMES;
        }
        if ("true".equals(props.get(Sasl.POLICY_FORWARD_SECRECY))) {
            return WildFlySasl.NO_NAMES;
        }
        if ("true".equals(props.get(Sasl.POLICY_NOPLAINTEXT))) {
            return WildFlySasl.NO_NAMES;
        }
        if ("true".equals(props.get(Sasl.POLICY_NOANONYMOUS))) {
            return WildFlySasl.NO_NAMES;
        }
        if ("true".equals(props.get(Sasl.POLICY_NODICTIONARY))) {
            return WildFlySasl.NO_NAMES;
        }
        if ("true".equals(props.get(Sasl.POLICY_PASS_CREDENTIALS))) {
            return WildFlySasl.NO_NAMES;
        }
        return Arrays2.of(SaslMechanismInformation.Names.EXTERNAL);
    }
}
