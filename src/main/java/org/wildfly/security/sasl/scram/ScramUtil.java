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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import org.wildfly.security.sasl.WildFlySasl;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramUtil {

    static int getIntProperty(final Map<String, ?> props, final String name, final int defVal) {
        final Object val = props.get(name);
        if (val == null) {
            return defVal;
        } else {
            return Integer.parseInt(val.toString());
        }
    }

    static SecureRandom getSecureRandom(final Map<String, ?> props) {
        final Object propVal = props.get(WildFlySasl.SECURE_RNG);
        final String rngName = propVal instanceof String ? (String) propVal : null;
        SecureRandom secureRandom = null;
        if (rngName != null) {
            try {
                secureRandom = SecureRandom.getInstance(rngName);
            } catch (NoSuchAlgorithmException ignored) {
            }
        }
        return secureRandom;
    }
}
