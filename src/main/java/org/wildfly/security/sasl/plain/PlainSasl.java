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

package org.wildfly.security.sasl.plain;

import java.util.Map;

import javax.security.sasl.Sasl;

import org.wildfly.security.sasl.WildFlySasl;

/**
 * The {@code PLAIN} SASL mechanism as described in <a href="http://www.ietf.org/rfc/rfc4616.txt">RFC 4616</a>.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PlainSasl {

    /**
     * The PLAIN mechanism name
     */
    public static final String PLAIN = "PLAIN";

    static final String[] NAMES = { PLAIN };

    static boolean isMatched(final Map<String, ?> props) {
        if ("true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL))) {
            return true;
        }
        if ("true".equals(props.get(Sasl.POLICY_NOACTIVE))) {
            return false;
        }
        if ("true".equals(props.get(Sasl.POLICY_NODICTIONARY))) {
            return false;
        }
        if ("true".equals(props.get(Sasl.POLICY_NOPLAINTEXT))) {
            return false;
        }
        if ("true".equals(props.get(Sasl.POLICY_FORWARD_SECRECY))) {
            return false;
        }
        if ("true".equals(props.get(Sasl.POLICY_PASS_CREDENTIALS))) {
            return false;
        }
        return true;
    }
}
