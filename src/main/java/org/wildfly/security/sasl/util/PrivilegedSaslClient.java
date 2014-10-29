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

import static java.security.AccessController.doPrivileged;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

/**
 * A {@code SaslClient} which evaluates challenges and wrap/unwrap requests in an privileged context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PrivilegedSaslClient extends AbstractDelegatingSaslClient implements SaslWrapper {
    private final AccessControlContext accessControlContext;

    PrivilegedSaslClient(final SaslClient delegate, final AccessControlContext accessControlContext) {
        super(delegate);
        if (delegate == null) {
            throw new IllegalArgumentException("delegate is null");
        }
        if (accessControlContext == null) {
            throw new IllegalArgumentException("accessControlContext is null");
        }
        this.accessControlContext = accessControlContext;
    }

    public PrivilegedSaslClient(final SaslClient delegate) {
        this(delegate, AccessController.getContext());
    }

    public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
        try {
            return doPrivileged(new PrivilegedExceptionAction<byte[]>() {
                public byte[] run() throws Exception {
                    return delegate.evaluateChallenge(challenge);
                }
            }, accessControlContext);
        } catch (PrivilegedActionException pae) {
            try {
                throw pae.getCause();
            } catch (SaslException | RuntimeException | Error e) {
                throw e;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
    }

    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        try {
            return doPrivileged(new PrivilegedExceptionAction<byte[]>() {
                public byte[] run() throws Exception {
                    return delegate.unwrap(incoming, offset, len);
                }
            });
        } catch (PrivilegedActionException pae) {
            try {
                throw pae.getCause();
            } catch (SaslException | RuntimeException | Error e) {
                throw e;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
    }

    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        try {
            return doPrivileged(new PrivilegedExceptionAction<byte[]>() {
                public byte[] run() throws Exception {
                    return delegate.wrap(outgoing, offset, len);
                }
            });
        } catch (PrivilegedActionException pae) {
            try {
                throw pae.getCause();
            } catch (SaslException | RuntimeException | Error e) {
                throw e;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
    }
}
