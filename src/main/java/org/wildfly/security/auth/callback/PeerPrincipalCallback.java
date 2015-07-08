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

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.Serializable;
import java.security.Principal;

/**
 * An optional callback to inform the callback handler of the peer's principal identity.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PeerPrincipalCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -2876104318406026491L;

    /**
     * @serial The peer principal.
     */
    private final Principal principal;

    /**
     * Construct a new instance.
     *
     * @param principal the peer principal
     */
    public PeerPrincipalCallback(final Principal principal) {
        if (principal == null) {
            throw log.nullParameter("principal");
        }
        this.principal = principal;
    }

    /**
     * Get the peer principal.
     *
     * @return the peer principal
     */
    public Principal getPrincipal() {
        return principal;
    }
}
