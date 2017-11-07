/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.GeneralName;

/**
 * An access description for the authority information access and subject information access extensions.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class AccessDescription implements ASN1Encodable {

    private final String accessMethodId;
    private final GeneralName accessLocation;

    /**
     * Construct a new instance.
     *
     * @param accessMethodId the access method OID (must not be {@code null})
     * @param accessLocation the access location (must not be {@code null})
     */
    public AccessDescription(final String accessMethodId, final GeneralName accessLocation) {
        Assert.checkNotNullParam("accessMethodId", accessMethodId);
        Assert.checkNotNullParam("accessLocation", accessLocation);
        this.accessMethodId = accessMethodId;
        this.accessLocation = accessLocation;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        encoder.encodeObjectIdentifier(accessMethodId);
        accessLocation.encodeTo(encoder);
        encoder.endSequence();
    }
}
