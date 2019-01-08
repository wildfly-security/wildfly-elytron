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

package org.wildfly.security.sasl.oauth2;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.mechanism._private.ElytronMessages;
import org.wildfly.security.mechanism.oauth2.OAuth2Client;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.util.Map;

/**
 * A {@link SaslClientFactory} for OAuth2.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(value = SaslClientFactory.class)
public final class OAuth2SaslClientFactory implements SaslClientFactory {

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        if (getMechanismNames(props, false).length == 0) return null;

        for (String mechanism : mechanisms) {
            if (SaslMechanismInformation.Names.OAUTHBEARER.equals(mechanism)) {
                return new OAuth2SaslClient(mechanism, protocol, serverName, cbh, authorizationId, new OAuth2Client(authorizationId, cbh, ElytronMessages.saslOAuth2));
            }
        }

        return null;
    }

    private String[] getMechanismNames(final Map<String, ?> props, boolean query) {
        if (props == null) {
            return new String[] {SaslMechanismInformation.Names.OAUTHBEARER};
        }

        if ("true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL)) && query) {
            return new String[] {SaslMechanismInformation.Names.OAUTHBEARER};
        }

        if ("true".equals(props.get(Sasl.POLICY_NOPLAINTEXT))
                || "true".equals(props.get(Sasl.POLICY_NOACTIVE))
                || "true".equals(props.get(Sasl.POLICY_NODICTIONARY))) {
            return new String[] {};
        }

        return new String[] {SaslMechanismInformation.Names.OAUTHBEARER};
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        return getMechanismNames(props, true);
    }


}
