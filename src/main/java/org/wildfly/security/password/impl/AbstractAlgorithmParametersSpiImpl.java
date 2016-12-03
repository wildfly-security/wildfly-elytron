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

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;

abstract class AbstractAlgorithmParametersSpiImpl<P extends AlgorithmParameterSpec> extends AlgorithmParametersSpi {

    private P parameterSpec;
    private byte[] encoded;

    AbstractAlgorithmParametersSpiImpl() {
    }

    protected abstract Class<P> getParameterType();

    protected void engineInit(final AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        final Class<P> parameterType = getParameterType();
        if (parameterType.isInstance(parameterSpec)) try {
            ByteStringBuilder b = new ByteStringBuilder();
            DEREncoder encoder = new DEREncoder(b);
            final P cast = parameterType.cast(paramSpec);
            engineEncode(encoder, cast);
            encoded = b.toArray();
            this.parameterSpec = cast;
        } catch (ASN1Exception e) {
            throw log.failedToEncode(e);
        } else {
            throw log.invalidParameterSpec(parameterType, paramSpec.getClass());
        }
    }

    protected void engineInit(final byte[] params) throws IOException {
        final ByteIterator bi = ByteIterator.ofBytes(params);
        final DERDecoder decoder = new DERDecoder(bi);
        try {
            parameterSpec = engineDecode(decoder);
            encoded = params;
        } catch (ASN1Exception e) {
            throw log.failedToDecode(e);
        }
    }

    protected void engineInit(final byte[] params, final String format) throws IOException {
        if ("ASN.1".equalsIgnoreCase(format)) {
            engineInit(params);
        } else {
            throw log.invalidFormat("ASN.1", format);
        }
    }

    protected abstract void engineEncode(final DEREncoder encoder, final P parameters);

    protected abstract P engineDecode(final DERDecoder decoder);

    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(final Class<T> type) throws InvalidParameterSpecException {
        checkInit();
        if (type.isAssignableFrom(getParameterType()) && type.isInstance(parameterSpec)) {
            return type.cast(parameterSpec);
        } else {
            throw log.invalidParameterSpec(getParameterType(), type);
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        checkInit();
        return encoded;
    }

    protected byte[] engineGetEncoded(final String format) throws IOException {
        checkInit();
        if ("ASN.1".equalsIgnoreCase(format)) {
            return engineGetEncoded();
        } else {
            throw log.invalidFormat("ASN.1", format);
        }
    }

    private void checkInit() {
        if (parameterSpec == null || encoded == null) {
            throw log.algorithmParametersNotInitialized();
        }
    }

    protected String engineToString() {
        return "Password algorithm parameters implementation";
    }
}
