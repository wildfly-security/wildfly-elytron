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

package org.wildfly.security.sasl.util;

import java.util.Arrays;

import javax.security.sasl.SaslException;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface SaslWrapper {

    /**
     * The identity wrapper which simply returns the same data that was passed in.  If the data is of a different size
     * then a copy is made.
     */
    SaslWrapper IDENTITY = new SaslWrapper() {
        public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
            if (offset == 0 && outgoing.length == len) {
                return outgoing;
            } else {
                return Arrays.copyOfRange(outgoing, offset, len);
            }
        }

        public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
            if (offset == 0 && incoming.length == len) {
                return incoming;
            } else {
                return Arrays.copyOfRange(incoming, offset, len);
            }
        }
    };

    byte[] wrap(byte[] outgoing, final int offset, final int len) throws SaslException;

    byte[] unwrap(byte[] incoming, final int offset, final int len) throws SaslException;
}
