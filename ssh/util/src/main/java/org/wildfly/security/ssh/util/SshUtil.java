/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.ssh.util;

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Iterator;
import java.util.NoSuchElementException;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.ssh.util._pivate.ElytronMessages.log;

/**
 * Class providing utilities for parsing of keys in OpenSSH format
 */
public class SshUtil {

    public static final String OPENSSH_PRIVATE_KEY_FORMAT = "OPENSSH PRIVATE KEY";


    /**
     * Iterate over the contents of a key file in OpenSSH format, returning each entry in sequence.
     *
     * @param pemContent the code point iterator over the content (must not be {@code null})
     * @param passphraseProvider provides the passphrase used to decrypt the private key(may be {@code null})
     * @return the iterator (not {@code null})
     * @throws IllegalArgumentException if there is a problem with the data or the key
     *
     */
    public static Iterator<PemEntry<?>> parsePemOpenSSHContent(CodePointIterator pemContent, FilePasswordProvider passphraseProvider) throws IllegalArgumentException {
        checkNotNullParam("pemContent", pemContent);
        return new Iterator<PemEntry<?>>() {
            private PemEntry<?> next;

            public boolean hasNext() {
                if (next == null) {
                    if (! pemContent.hasNext()) {
                        return false;
                    }
                    next = Pem.parsePemContent(pemContent, (type, byteIterator) -> {
                        switch (type) {
                            case OPENSSH_PRIVATE_KEY_FORMAT: {
                                final KeyPair keyPair = parseOpenSSHKeys(byteIterator, passphraseProvider);
                                return new PemEntry<>(keyPair);
                            }
                            default: {
                                throw log.malformedSshPemContent(pemContent.getIndex());
                            }
                        }
                    });
                    if (next == null) {
                        return false;
                    }
                }
                return true;
            }

            public PemEntry<?> next() {
                if (! hasNext()) {
                    throw new NoSuchElementException();
                }
                try {
                    return next;
                } finally {
                    next = null;
                }
            }
        };
    }

    private static KeyPair parseOpenSSHKeys(ByteIterator byteIterator, FilePasswordProvider passphraseProvider) throws IllegalArgumentException {
        OpenSSHKeyPairResourceParser resourceParser = new OpenSSHKeyPairResourceParser();
        byte[] stream = byteIterator.drain();
        try {
            return  resourceParser.extractKeyPairs(null, null,
                    OpenSSHKeyPairResourceParser.BEGIN_MARKER, OpenSSHKeyPairResourceParser.END_MARKER,
                    passphraseProvider, stream, null).iterator().next();
        } catch (IOException e) {
            throw log.openSshParseError(e.getMessage());
        } catch (GeneralSecurityException e) {
            throw log.openSshGeneratingError(e.getMessage());
        }
    }

}
