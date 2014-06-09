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

package org.wildfly.sasl.gssapi;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

/**
 * A wrapper around a {@link SaslServer} to ensure appropriate methods are called with a PrivilegedAction.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SubjectWrappingSaslServer implements SaslServer {

    private final SaslServer wrapped;
    private final Subject subject;

    SubjectWrappingSaslServer(SaslServer toBeWrapped, Subject subject) {
        this.wrapped = toBeWrapped;
        this.subject = subject;
    }

    @Override
    public String getMechanismName() {
        return wrapped.getMechanismName();
    }

    @Override
    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        try {
            return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {

                @Override
                public byte[] run() throws Exception {
                    return wrapped.evaluateResponse(response);
                }
            });
        } catch (PrivilegedActionException e) {
            if (e.getCause() instanceof SaslException) {
                throw (SaslException) e.getCause();
            }
            throw new SaslException(e.getMessage(), e);
        }
    }

    @Override
    public boolean isComplete() {
        return wrapped.isComplete();
    }

    @Override
    public String getAuthorizationID() {
        return wrapped.getAuthorizationID();
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        return wrapped.unwrap(incoming, offset, len);
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        return wrapped.wrap(outgoing, offset, len);
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        return wrapped.getNegotiatedProperty(propName);
    }

    @Override
    public void dispose() throws SaslException {
        wrapped.dispose();
    }

}
