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
import org.wildfly.security.mechanism.oauth2.OAuth2Server;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.util.Map;

/**
 * A {@link SaslServerFactory} for OAuth2.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(value = SaslServerFactory.class)
public final class OAuth2SaslServerFactory implements SaslServerFactory {

    public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
        if (getMechanismNames(props, false).length == 0) return null;

        switch (mechanism) {
            case SaslMechanismInformation.Names.OAUTHBEARER:
                return new OAuth2SaslServer(mechanism, protocol, serverName, cbh, new OAuth2Server(cbh, props, ElytronMessages.saslOAuth2));
            default: {
                return null;
            }
        }
    }

    private String[] getMechanismNames(Map<String, ?> props, boolean query) {
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
