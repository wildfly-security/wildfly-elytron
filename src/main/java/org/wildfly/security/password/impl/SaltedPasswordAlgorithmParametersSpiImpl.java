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

package org.wildfly.security.password.impl;

import java.security.AlgorithmParametersSpi;

import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

/**
 * An implementation of the {@link AlgorithmParametersSpi} SPI, in order to support encoding and decoding of
 * password algorithm parameters.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaltedPasswordAlgorithmParametersSpiImpl extends AbstractAlgorithmParametersSpiImpl<SaltedPasswordAlgorithmSpec> {

    /**
     * Construct a new instance.
     */
    public SaltedPasswordAlgorithmParametersSpiImpl() {
    }

    protected Class<SaltedPasswordAlgorithmSpec> getParameterType() {
        return SaltedPasswordAlgorithmSpec.class;
    }

    protected void engineEncode(final DEREncoder encoder, final SaltedPasswordAlgorithmSpec parameterSpec) {
        encoder.encodeOctetString(parameterSpec.getSalt());
    }

    protected SaltedPasswordAlgorithmSpec engineDecode(final DERDecoder decoder) {
        final byte[] salt = decoder.decodeOctetString();
        return new SaltedPasswordAlgorithmSpec(salt);
    }
}
