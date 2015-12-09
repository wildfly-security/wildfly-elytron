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
package org.wildfly.security.credential.store.impl;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import org.wildfly.common.Assert;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * Class to wrap {@code byte[]} to be able to store it in {@link java.security.KeyStore}
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class SecretKeyWrap implements SecretKey, Serializable {

    private static final long serialVersionUID = -4338788143408230538L;
    private byte[] bytes;
    private String algorithm;

    /**
     * Create {@code SecretKeyWrap} of {@code byte[]}.
     * @param bytes to wrap
     * @param algorithm name of algorithm for this wrap
     */
    public SecretKeyWrap(byte[] bytes, String algorithm) {
        Assert.assertNotNull(bytes);
        Assert.assertNotNull(algorithm);
        this.bytes = bytes;
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return bytes;
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        byte[] algorithmName = algorithm.getBytes(StandardCharsets.UTF_8);
        ByteStringBuilder b = new ByteStringBuilder();
        b.appendBE(algorithmName.length);
        b.append(algorithmName);
        b.append(bytes);
        out.writeObject(b.toArray());
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        ByteIterator bi = ByteIterator.ofBytes((byte[]) in.readObject());
        int algorithmBytesLength = bi.getBE32();
        algorithm = bi.drainToUtf8(algorithmBytesLength);
        bytes = bi.drain();
    }

}
