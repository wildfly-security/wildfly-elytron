/*
 * JBoss, Home of Professional Open Source
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

import java.security.Provider;

import org.wildfly.security.ServiceImplementationFactory;

/**
 * Provides the password service implementations of this module to the Elytron providers.
 */
public final class PasswordImplementationFactory implements ServiceImplementationFactory {

    @Override
    public Object newInstance(final String className, final Provider provider) {
        if (className.equals(PasswordFactorySpiImpl.class.getName())) {
            return new PasswordFactorySpiImpl();
        }
        if (className.equals(DigestPasswordAlgorithmParametersSpiImpl.class.getName())) {
            return new DigestPasswordAlgorithmParametersSpiImpl();
        }
        if (className.equals(IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName())) {
            return new IteratedSaltedPasswordAlgorithmParametersSpiImpl();
        }
        if (className.equals(MaskedPasswordAlgorithmParametersSpiImpl.class.getName())) {
            return new MaskedPasswordAlgorithmParametersSpiImpl();
        }
        if (className.equals(OneTimePasswordAlgorithmParametersSpiImpl.class.getName())) {
            return new OneTimePasswordAlgorithmParametersSpiImpl();
        }
        if (className.equals(SaltedPasswordAlgorithmParametersSpiImpl.class.getName())) {
            return new SaltedPasswordAlgorithmParametersSpiImpl();
        }
        return null;
    }
}
