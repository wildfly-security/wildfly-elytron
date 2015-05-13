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

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;

/**
 * A callback used to acquire parameter specifications, either for outbound or inbound authentication.
 * The supplied parameter specification should be of a <em>supported</em>
 * type; the {@link #isParameterSupported(AlgorithmParameterSpec)} and {@link #isParameterTypeSupported(Class)} methods can be
 * used to query the types that are supported.  If no credential is available, {@code null} is set, and
 * authentication may fail.  If an unsupported credential type is set, authentication may fail.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ParameterCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -6000106115779144082L;

    /**
     * @serial The list of allowed parameter specification types.
     */
    private final Class<? extends AlgorithmParameterSpec>[] allowedTypes;
    /**
     * @serial The algorithm parameter specification.
     */
    private AlgorithmParameterSpec parameterSpec;

    /**
     * Construct a new instance.
     *
     * @param allowedTypes the allowed types of parameter specification
     */
    @SafeVarargs
    public ParameterCallback(final Class<? extends AlgorithmParameterSpec>... allowedTypes) {
        this.allowedTypes = allowedTypes;
    }

    /**
     * Construct a new instance.
     *
     * @param parameterSpec the default parameter spec value, if any
     * @param allowedTypes the allowed types of parameter spec
     */
    @SafeVarargs
    public ParameterCallback(final AlgorithmParameterSpec parameterSpec, final Class<? extends AlgorithmParameterSpec>... allowedTypes) {
        this.allowedTypes = allowedTypes;
        this.parameterSpec = parameterSpec;
    }

    /**
     * Get the parameter specification.
     *
     * @return the parameter specification, or {@code null} if it wasn't set yet
     */
    public AlgorithmParameterSpec getParameterSpec() {
        return parameterSpec;
    }

    /**
     * Set the parameter specification.
     *
     * @param parameterSpec the parameter specification, or {@code null} if no parameter specification is available
     */
    public void setParameterSpec(final AlgorithmParameterSpec parameterSpec) {
        if (! isParameterSupported(parameterSpec)) {
            throw new IllegalArgumentException("Invalid credential type specified");
        }
        this.parameterSpec = parameterSpec;
    }

    /**
     * Determine whether a parameter specification would be supported by the authentication.
     *
     * @param parameterSpec the parameter specification to test
     * @return {@code true} if the parameter specification is non-{@code null} and supported, {@code false} otherwise
     */
    public boolean isParameterSupported(final AlgorithmParameterSpec parameterSpec) {
        for (final Class<?> allowedType : allowedTypes) {
            if (allowedType.isInstance(parameterSpec)) return true;
        }
        return false;
    }

    /**
     * Determine whether a credential type would be supported by the authentication.
     *
     * @param parameterType the parameter specification type to test
     * @return {@code true} if the parameter specification type is supported, {@code false} otherwise
     */
    public boolean isParameterTypeSupported(final Class<? extends AlgorithmParameterSpec> parameterType) {
        for (final Class<? extends AlgorithmParameterSpec> allowedType : allowedTypes) {
            if (allowedType.isAssignableFrom(parameterType)) return true;
        }
        return false;
    }

    public boolean isOptional() {
        return parameterSpec != null;
    }

    public boolean needsInformation() {
        return true;
    }
}
