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

package org.wildfly.security.util;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.wildfly.security.asn1.ASN1Decoder;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;

/**
 * A base class for classes which implement {@link AlgorithmParametersSpi} that encode parameters using ASN.1.
 *
 * @param <P> the parameter type represented by the subclass
 */
public abstract class AbstractAlgorithmParametersSpiImpl<P extends AlgorithmParameterSpec> extends AlgorithmParametersSpi {

    private P parameterSpec;
    private byte[] encoded;

    /**
     * Construct a new instance.
     */
    protected AbstractAlgorithmParametersSpiImpl() {
    }

    /**
     * Get the type of parameters for this class.
     *
     * @return the type of parameters for this class (must not be {@code null})
     */
    protected abstract Class<P> getParameterType();

    /**
     * Implementation of the {@code engineInit} method.
     *
     * @param paramSpec the parameter specification
     * @throws InvalidParameterSpecException if an argument is invalid or encoding failed
     */
    protected final void engineInit(final AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        final Class<P> parameterType = getParameterType();
        if (parameterType.isInstance(paramSpec)) try {
            DEREncoder encoder = new DEREncoder();
            final P cast = parameterType.cast(paramSpec);
            engineEncode(encoder, cast);
            encoded = encoder.getEncoded();
            this.parameterSpec = cast;
        } catch (ASN1Exception e) {
            throw log.failedToEncode(e);
        } else {
            throw log.invalidParameterSpec(parameterType, paramSpec.getClass());
        }
    }

    /**
     * Implementation of the {@code engineInit} method.
     *
     * @param params the encoded parameter specification
     * @throws IOException if decoding failed
     */
    protected final void engineInit(final byte[] params) throws IOException {
        final DERDecoder decoder = new DERDecoder(params);
        try {
            parameterSpec = engineDecode(decoder);
            encoded = params;
        } catch (ASN1Exception e) {
            throw log.failedToDecode(e);
        }
    }

    /**
     * Implementation of the {@code engineInit} method.
     *
     * @param params the encoded parameter specification
     * @param format the format (must be {@code ASN.1})
     * @throws IOException if decoding failed or the format is not equal to {@code ASN.1}
     */
    protected final void engineInit(final byte[] params, final String format) throws IOException {
        if ("ASN.1".equalsIgnoreCase(format)) {
            engineInit(params);
        } else {
            throw log.invalidFormat("ASN.1", format);
        }
    }

    /**
     * Encode a parameter instance.
     *
     * @param encoder the encoder to use (not {@code null})
     * @param parameters the parameter instance (not {@code null})
     * @throws ASN1Exception if there is an encoding problem (usually thrown directly by the {@code ASN1Encoder})
     * @throws InvalidParameterSpecException if some other encoding error occurred
     */
    protected abstract void engineEncode(final ASN1Encoder encoder, final P parameters) throws ASN1Exception, InvalidParameterSpecException;

    /**
     * Decode a parameter instance.  Subclasses should ensure that all elements are consumed (including sequence terminators
     * and so forth).
     *
     * @param decoder the decoder to use (not {@code null})
     * @return the parameter instance (must not be {@code null})
     * @throws ASN1Exception if there is a decoding problem (usually thrown directly by the {@code ASN1Decoder})
     * @throws IOException if some other decoding error occurred
     */
    protected abstract P engineDecode(final ASN1Decoder decoder) throws ASN1Exception, IOException;

    /**
     * Implementation of the {@code engineGetParameterSpec} method.
     *
     * @param type the parameter specification type class (must not be {@code null})
     * @param <T> the parameter specification type
     * @return the parameter specification (must not be {@code null})
     * @throws InvalidParameterSpecException if the type is not supported
     */
    protected final <T extends AlgorithmParameterSpec> T engineGetParameterSpec(final Class<T> type) throws InvalidParameterSpecException {
        checkInit();
        if (type.isAssignableFrom(getParameterType()) && type.isInstance(parameterSpec)) {
            return type.cast(parameterSpec);
        } else {
            throw log.invalidParameterSpec(getParameterType(), type);
        }
    }

    /**
     * Implementation of the {@code engineGetEncoded} method.
     *
     * @return the encoded representation (not {@code null})
     */
    protected final byte[] engineGetEncoded() {
        checkInit();
        return encoded;
    }

    /**
     * Implementation of the {@code engineGetEncoded} method.
     *
     * @param format the format string (must not be {@code null})
     * @return the encoded representation (not {@code null})
     * @throws IOException if the given format is not {@code ASN.1}
     */
    protected final byte[] engineGetEncoded(final String format) throws IOException {
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

    /**
     * Implementation of the {@code engineToString} method.
     *
     * @return the string representation
     */
    protected String engineToString() {
        return "AlgorithmParametersSpi for " + getParameterType();
    }
}
