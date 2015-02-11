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

package org.wildfly.security.password.impl;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.Normalizer;

import org.wildfly.security.password.Password;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
abstract class AbstractPasswordImpl implements Password {

    private static final long serialVersionUID = -7527865607883174548L;

    abstract <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException;

    abstract boolean verify(final char[] guess) throws InvalidKeyException;

    abstract <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType);

    static byte[] getNormalizedPasswordBytes(final char[] characters) {
        return Normalizer.normalize(new String(characters), Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }


}
