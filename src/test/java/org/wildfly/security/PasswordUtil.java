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

package org.wildfly.security;

import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Utility for creating {@link ClearPassword} instances.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PasswordUtil {

    private static final PasswordFactory PASSWORD_FACTORY = getPasswordFactory();

    private PasswordUtil() {
    }

    private static PasswordFactory getPasswordFactory() {
        try {
            return PasswordFactory.getInstance(ALGORITHM_CLEAR);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static ClearPassword clearPassword(final char[] value) throws InvalidKeySpecException {
        ClearPasswordSpec spec = new ClearPasswordSpec(value);

        return (ClearPassword) PASSWORD_FACTORY.generatePassword(spec);
    }
}
