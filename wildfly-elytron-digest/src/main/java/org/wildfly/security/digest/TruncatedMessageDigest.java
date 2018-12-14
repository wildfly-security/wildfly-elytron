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

package org.wildfly.security.digest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Arrays;

import org.wildfly.common.Assert;

/**
 * A message digest that truncates another message digest.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class TruncatedMessageDigest extends MessageDigest {

    private final MessageDigest delegate;
    private final int bytes;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate message digest
     * @param bytes the truncation size
     */
    public TruncatedMessageDigest(final MessageDigest delegate, final int bytes) {
        super(delegate.getAlgorithm());
        this.delegate = delegate;
        this.bytes = bytes;
    }

    @Override
    public void update(final byte input) {
        delegate.update(input);
    }

    @Override
    public void update(final byte[] input, final int offset, final int len) {
        delegate.update(input, offset, len);
    }

    @Override
    public void update(final byte[] input) {
        delegate.update(input);
    }

    @Override
    public byte[] digest() {
        final byte[] digest = delegate.digest();
        return digest.length > bytes ? Arrays.copyOf(digest, bytes) : digest;
    }

    @Override
    public int digest(final byte[] buf, final int offset, final int len) throws DigestException {
        Assert.checkNotNullParam("buf", buf);
        if (bytes > len) {
            // exactly match the JDK message
            throw new IllegalArgumentException("Output buffer too small for specified offset and length");
        }
        System.arraycopy(delegate.digest(), 0, buf, offset, bytes);
        return bytes;
    }

    @Override
    public byte[] digest(final byte[] input) {
        update(input);
        return digest();
    }

    @Override
    public void reset() {
        delegate.reset();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        return new TruncatedMessageDigest((MessageDigest) delegate.clone(), bytes);
    }

    @Override
    protected void engineUpdate(final byte input) {
    }

    @Override
    protected void engineUpdate(final byte[] input, final int offset, final int len) {
    }

    @Override
    protected byte[] engineDigest() {
        return null;
    }

    @Override
    protected void engineReset() {
    }
}
