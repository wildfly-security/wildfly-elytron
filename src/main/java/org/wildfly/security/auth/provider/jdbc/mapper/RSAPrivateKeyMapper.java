/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.provider.jdbc.mapper;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.provider.jdbc.KeyMapper;
import org.wildfly.security.auth.spi.CredentialSupport;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.ResultSet;

/**
 * A {@link KeyMapper} that knows how to map columns to a RSA {@link PrivateKey}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RSAPrivateKeyMapper implements KeyMapper {

    private static final String KEY_ALGORITHM = "RSA";

    private final int privateKey;

    /**
     * Creates a new instance.
     *
     * @param privateKey The column index from where an array of bytes are read in order to create the private key.
     */
    public RSAPrivateKeyMapper(int privateKey) {
        Assert.checkMinimumParameter("privateKey", 1, privateKey);
        this.privateKey = privateKey;
    }

    /**
     * Returns an integer representing the column index from where an array of bytes are obtained in order to create the
     * private key.
     *
     * @return the column index
     */
    public int getPrivateKey() {
        return this.privateKey;
    }

    @Override
    public Class<?> getKeyType() {
        return PrivateKey.class;
    }

    @Override
    public CredentialSupport getCredentialSupport(ResultSet resultSet) {
        Object map = map(resultSet);

        if (map != null) {
            return CredentialSupport.OBTAINABLE_ONLY;
        }

        return CredentialSupport.UNSUPPORTED;
    }

    @Override
    public Object map(ResultSet resultSet) {
        Object privateKey = null;

        try {
            if (resultSet.next()) {
                privateKey = resultSet.getObject(getPrivateKey());
            }
        } catch (Exception e) {
            throw new RuntimeException("Could not RSA key from query.", e);
        }

        if (privateKey != null) {
            try {
                KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
                return kf.generatePrivate(new PKCS8EncodedKeySpec((byte[]) privateKey));
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Invalid algorithm [" + KEY_ALGORITHM + "].", e);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException("Could not parse private key.", e);
            }
        }

        return null;
    }
}
