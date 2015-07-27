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

package org.wildfly.security.sasl.digest;

import java.util.Map;

import javax.security.sasl.Sasl;

import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class AbstractDigestFactory {

    private static final String[] MECHS = {
        SaslMechanismInformation.Names.DIGEST_SHA_512,
        SaslMechanismInformation.Names.DIGEST_SHA_256,
        SaslMechanismInformation.Names.DIGEST_SHA,
        SaslMechanismInformation.Names.DIGEST_MD5,
    };
    private static final String[] NO_MECHS = new String[0];

    @SuppressWarnings("RedundantIfStatement")
    boolean matches(final Map<String, ?> props) {
        if ("true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL))) {
            return true;
        }
        if ("true".equals(props.get(Sasl.POLICY_FORWARD_SECRECY))
            || "true".equals(props.get(Sasl.POLICY_PASS_CREDENTIALS))
            || "true".equals(props.get(Sasl.POLICY_NODICTIONARY))
            || "true".equals(props.get(Sasl.POLICY_NOACTIVE))) {
            return false;
        }
        return true;
    }

    boolean matchesMech(String mechanismName) {
        switch (mechanismName) {
            case SaslMechanismInformation.Names.DIGEST_MD5:
            case SaslMechanismInformation.Names.DIGEST_SHA:
            case SaslMechanismInformation.Names.DIGEST_SHA_256:
            case SaslMechanismInformation.Names.DIGEST_SHA_512: {
                return true;
            }
        }
        return false;
    }

    String select(String[] mechanismNames) {
        for (String mechanismName : mechanismNames) {
            if (matchesMech(mechanismName)) return mechanismName;
        }
        return null;
    }

    public String[] getMechanismNames(final Map<String, ?> props) {
        return matches(props) ? MECHS.clone() : NO_MECHS;
    }
}
