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

package org.wildfly.security.auth.callback;

import java.net.SocketAddress;

/**
 * An optional callback which is used to inform the callback handler of the endpoint addresses of a connection being
 * authenticated.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SocketAddressCallback extends AbstractExtendedCallback {

    private static final long serialVersionUID = -4287450716990929230L;

    private final SocketAddress address;
    private final Kind kind;

    /**
     * Construct a new instance.
     *
     * @param address the endpoint socket address
     * @param kind the disposition of the endpoint
     */
    public SocketAddressCallback(final SocketAddress address, final Kind kind) {
        if (address == null) {
            throw new IllegalArgumentException("address is null");
        }
        if (kind == null) {
            throw new IllegalArgumentException("kind is null");
        }
        this.address = address;
        this.kind = kind;
    }

    /**
     * Construct a new instance.  The disposition is assumed to be {@link Kind#PEER}.
     *
     * @param address the endpoint socket address
     */
    public SocketAddressCallback(final SocketAddress address) {
        this(address, Kind.PEER);
    }

    /**
     * Get the endpoint socket address.
     *
     * @return the endpoint socket address
     */
    public SocketAddress getAddress() {
        return address;
    }

    /**
     * Get the endpoint disposition.
     *
     * @return the endpoint disposition
     */
    public Kind getKind() {
        return kind;
    }

    /**
     * Endpoint disposition kinds.
     */
    public enum Kind {
        /**
         * The local endpoint.
         */
        LOCAL,
        /**
         * The remote (peer) endpoint.
         */
        PEER,
        ;
    }
}
