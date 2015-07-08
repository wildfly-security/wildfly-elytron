/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500;

import java.security.Principal;
import java.util.Arrays;
import java.util.stream.Collectors;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.auth.server.PrincipalDecoder;

/**
 * A principal decoder which decodes an attribute from an X.500 principal.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500AttributePrincipalDecoder implements PrincipalDecoder {
    private final String oid;
    private final String joiner;
    private final int maximumSegments;

    /**
     * Construct a new instance.  A joining string of "." is assumed.
     *
     * @param oid the OID of the attribute to map
     */
    public X500AttributePrincipalDecoder(final String oid) {
        this(oid, ".", Integer.MAX_VALUE);
    }

    /**
     * Construct a new instance.  A joining string of "." is assumed.
     *
     * @param oid the OID of the attribute to map
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     */
    public X500AttributePrincipalDecoder(final String oid, final int maximumSegments) {
        this(oid, ".", maximumSegments);
    }

    /**
     * Construct a new instance.
     *
     * @param oid the OID of the attribute to map
     * @param joiner the joining string
     */
    public X500AttributePrincipalDecoder(final String oid, final String joiner) {
        this(oid, joiner, Integer.MAX_VALUE);
    }

    /**
     * Construct a new instance.
     *
     * @param oid the OID of the attribute to map
     * @param joiner the joining string
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     */
    public X500AttributePrincipalDecoder(final String oid, final String joiner, final int maximumSegments) {
        this.oid = oid;
        this.joiner = joiner;
        this.maximumSegments = maximumSegments;
    }

    public String getName(final Principal principal) {
        final X500Principal x500Principal = X500PrincipalUtil.asX500Principal(principal);
        if (x500Principal == null) {
            return null;
        }
        final String[] values = X500PrincipalUtil.getAttributeValues(x500Principal, oid);
        if (values.length == 0) {
            return null;
        } else {
            return Arrays.stream(values).limit(maximumSegments).collect(Collectors.joining(joiner));
        }
    }
}
