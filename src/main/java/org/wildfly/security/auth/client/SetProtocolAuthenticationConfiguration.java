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

/**
 * An {@link AuthenticationConfiguration} that sets the protocol reported to the authentication mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SetProtocolAuthenticationConfiguration extends AuthenticationConfiguration {

    private final String protocol;
    SetProtocolAuthenticationConfiguration(final AuthenticationConfiguration parent, final String protocol) {
        super(parent);
        this.protocol = protocol;
    }

    @Override
    String getProtocol() {
        return protocol;
    }

    @Override
    AuthenticationConfiguration reparent(AuthenticationConfiguration newParent) {
        return new SetProtocolAuthenticationConfiguration(newParent, protocol);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return protocol.equals(other.getProtocol()) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 10391, protocol.hashCode());
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("protocol=").append(protocol).append(',');
    }

}
