/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.vault._private;

import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Class to wrap {@link ClearPassword} to be able to store it in {@link java.security.KeyStore}
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
class SecretKeyWrap implements SecretKey, Serializable {

    private static final long serialVersionUID = -4338788143408230538L;
    private ClearPassword password;

    SecretKeyWrap(ClearPassword password) {
        this.password = password;
    }

    @Override
    public String getAlgorithm() {
        return password.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return password.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return password.getEncoded();
    }

    @Override
    public void destroy() throws DestroyFailedException {
        password.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return password.isDestroyed();
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.writeObject(password.getEncoded());
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        byte[] encoded = (byte[]) in.readObject();

        final PasswordFactory passwordFactory;
        try {
            passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
            password = (ClearPassword) passwordFactory.generatePassword(new ClearPasswordSpec(ElytronVault.byteArrayDecode(encoded)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IOException(e);
        }
    }
}
