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

package org.wildfly.security.auth.client;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetPortAuthenticationConfiguration extends AuthenticationConfiguration {

    private final int port;

    SetPortAuthenticationConfiguration(final AuthenticationConfiguration parent, final int port) {
        super(parent);
        this.port = port;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetPortAuthenticationConfiguration(newParent, port);
    }

    int getPort() {
        return port;
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("port=").append(port).append(',');
    }

}
