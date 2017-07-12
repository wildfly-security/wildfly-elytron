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

import org.wildfly.security.asn1.ASN1Decoder;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;
import org.wildfly.security.util.AbstractAlgorithmParametersSpiImpl;

/**
 * An implementation of the {@link AlgorithmParametersSpi} SPI, in order to support encoding and decoding of
 * password algorithm parameters.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class OneTimePasswordAlgorithmParametersSpiImpl extends AbstractAlgorithmParametersSpiImpl<OneTimePasswordAlgorithmSpec> {

    /**
     * Construct a new instance.
     */
    public OneTimePasswordAlgorithmParametersSpiImpl() {
    }

    protected Class<OneTimePasswordAlgorithmSpec> getParameterType() {
        return OneTimePasswordAlgorithmSpec.class;
    }

    protected void engineEncode(final ASN1Encoder encoder, final OneTimePasswordAlgorithmSpec parameterSpec) {
        encoder.startSequence();
        encoder.encodeOctetString(parameterSpec.getAlgorithm());
        encoder.encodeIA5String(parameterSpec.getSeed());
        encoder.encodeInteger(parameterSpec.getSequenceNumber());
        encoder.endSequence();
    }

    protected OneTimePasswordAlgorithmSpec engineDecode(final ASN1Decoder decoder) {
        decoder.startSequence();
        final String algorithm = decoder.decodeOctetStringAsString();
        final String seed = decoder.decodeIA5String();
        final int sequenceNumber = decoder.decodeInteger().intValue();
        decoder.endSequence();
        return new OneTimePasswordAlgorithmSpec(algorithm, seed, sequenceNumber);
    }
}
