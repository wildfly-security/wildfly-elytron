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

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.x500.util.X500PrincipalUtil;

/**
 * A principal decoder which decodes an attribute from an X.500 principal.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500AttributePrincipalDecoder implements PrincipalDecoder {
    private static final String[] NO_REQUIRED_OIDS = new String[0];

    private final String oid;
    private final String joiner;
    private final int startSegment;
    private final int maximumSegments;
    private final boolean reverse;
    private final String[] requiredOids;
    private final boolean convert;

    /**
     * Construct a new instance.  A joining string of "." is assumed.
     *
     * @param oid the OID of the attribute to map
     */
    public X500AttributePrincipalDecoder(final String oid) {
        this(oid, false);
    }

    /**
     * Construct a new instance.  A joining string of "." is assumed.
     *
     * @param oid the OID of the attribute to map
     * @param reverse {@code true} if the attribute values should be processed and returned in reverse order
     */
    public X500AttributePrincipalDecoder(final String oid, final boolean reverse) {
        this(oid, ".", 0, Integer.MAX_VALUE, reverse);
    }

    /**
     * Construct a new instance.  A joining string of "." is assumed.
     *
     * @param oid the OID of the attribute to map
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     */
    public X500AttributePrincipalDecoder(final String oid, final int maximumSegments) {
        this(oid, maximumSegments, false);
    }

    /**
     * Construct a new instance.  A joining string of "." is assumed.
     *
     * @param oid the OID of the attribute to map
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     * @param reverse {@code true} if the attribute values should be processed and returned in reverse order
     */
    public X500AttributePrincipalDecoder(final String oid, final int maximumSegments, final boolean reverse) {
        this(oid, ".", 0, maximumSegments, reverse);
    }

    /**
     * Construct a new instance.  A joining string of "." is assumed.
     *
     * @param oid the OID of the attribute to map
     * @param startSegment the 0-based starting occurrence of the attribute to map
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     */
    public X500AttributePrincipalDecoder(final String oid, final int startSegment, final int maximumSegments) {
        this(oid, startSegment, maximumSegments, false);
    }

    /**
     * Construct a new instance.  A joining string of "." is assumed.
     *
     * @param oid the OID of the attribute to map
     * @param startSegment the 0-based starting occurrence of the attribute to map
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     * @param reverse {@code true} if the attribute values should be processed and returned in reverse order
     */
    public X500AttributePrincipalDecoder(final String oid, final int startSegment, final int maximumSegments, final boolean reverse) {
        this(oid, ".", startSegment, maximumSegments, reverse);
    }

    /**
     * Construct a new instance.
     *
     * @param oid the OID of the attribute to map
     * @param joiner the joining string
     */
    public X500AttributePrincipalDecoder(final String oid, final String joiner) {
        this(oid, joiner, false);
    }

    /**
     * Construct a new instance.
     *
     * @param oid the OID of the attribute to map
     * @param joiner the joining string
     * @param reverse {@code true} if the attribute values should be processed and returned in reverse order
     */
    public X500AttributePrincipalDecoder(final String oid, final String joiner, final boolean reverse) {
        this(oid, joiner, 0, Integer.MAX_VALUE, reverse);
    }

    /**
     * Construct a new instance.
     *
     * @param oid the OID of the attribute to map
     * @param joiner the joining string
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     */
    public X500AttributePrincipalDecoder(final String oid, final String joiner, final int maximumSegments) {
        this(oid, joiner, 0, maximumSegments, false);
    }

    /**
     * Construct a new instance.
     *
     * @param oid the OID of the attribute to map
     * @param joiner the joining string
     * @param startSegment the 0-based starting occurrence of the attribute to map
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     * @param reverse {@code true} if the attribute values should be processed and returned in reverse order
     */
    public X500AttributePrincipalDecoder(final String oid, final String joiner, final int startSegment, final int maximumSegments, final boolean reverse) {
        this(oid, joiner, startSegment, maximumSegments, reverse, false, NO_REQUIRED_OIDS);
    }

    /**
     * Construct a new instance.
     *
     * @param oid the OID of the attribute to map
     * @param joiner the joining string
     * @param startSegment the 0-based starting occurrence of the attribute to map
     * @param maximumSegments the maximum number of occurrences of the attribute to map
     * @param reverse {@code true} if the attribute values should be processed and returned in reverse order
     * @param convert {@code true} if the Principal should be converted to {@link X500Principal} if not one already
     * @param requiredOids the OIDs of the attributes that must be present
     */
    public X500AttributePrincipalDecoder(final String oid, final String joiner, final int startSegment, final int maximumSegments,
                                         final boolean reverse, final boolean convert, final String... requiredOids) {
        this.oid = oid;
        this.joiner = joiner;
        this.startSegment = startSegment;
        this.maximumSegments = maximumSegments;
        this.reverse = reverse;
        this.convert = convert;
        this.requiredOids = requiredOids;
    }

    public String getName(final Principal principal) {
        final X500Principal x500Principal = X500PrincipalUtil.asX500Principal(principal, convert);
        if (x500Principal == null) {
            return null;
        }
        if (requiredOids != null && requiredOids.length != 0 && ! X500PrincipalUtil.containsAllAttributes(x500Principal, requiredOids)) {
            ElytronMessages.log.tracef("X500 principal [%s] was not decoded - does not contain required oids", x500Principal);
            return null;
        }
        final String[] values = X500PrincipalUtil.getAttributeValues(x500Principal, oid, reverse);
        if (values.length == 0) {
            ElytronMessages.log.tracef("X500 principal [%s] was not decoded - no values of attribute [%s]", x500Principal, oid);
            return null;
        } else {
            final String name = Arrays.stream(values).skip(startSegment).limit(maximumSegments).collect(Collectors.joining(joiner));
            if (ElytronMessages.log.isTraceEnabled()) {
                ElytronMessages.log.tracef("X500 principal [%s] decoded as name [%s] (attribute values: [%s])", x500Principal, name, String.join(", ", values));
            }
            return name;
        }
    }
}
