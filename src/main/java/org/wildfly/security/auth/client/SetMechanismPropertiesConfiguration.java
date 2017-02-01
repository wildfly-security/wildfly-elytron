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
package org.wildfly.security.auth.client;

import static org.wildfly.common.math.HashMath.multiHashUnordered;

import java.util.HashMap;
import java.util.Map;

/**
 * An {@link AuthenticationConfiguration} to set mechanism properties.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SetMechanismPropertiesConfiguration extends AuthenticationConfiguration {

    private final Map<String, String> mechanismProperties;

    SetMechanismPropertiesConfiguration(AuthenticationConfiguration parent, Map<String, String> mechanismProperties) {
        super(parent);
        this.mechanismProperties = new HashMap<> (mechanismProperties);
    }

    @Override
    AuthenticationConfiguration reparent(AuthenticationConfiguration newParent) {
        return new SetMechanismPropertiesConfiguration(newParent, mechanismProperties);
    }

    @Override
    void configureSaslProperties(Map<String, Object> properties) {
        super.configureSaslProperties(properties);
        properties.putAll(mechanismProperties);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return mechanismProperties.equals(other.getMechanismProperties()) && parentHalfEqual(other);
    }

    Map<String, String> getMechanismProperties() {
        return mechanismProperties;
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 10267, mechanismProperties.hashCode());
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        parentAsString(sb);
        sb.append("mechanism-properties=[ ");
        if (mechanismProperties != null) {
            mechanismProperties.entrySet().forEach(e -> sb.append(e.getKey()).append('=').append(e.getValue()).append(' '));
        }
        sb.append("],");
        return sb;
    }

}
