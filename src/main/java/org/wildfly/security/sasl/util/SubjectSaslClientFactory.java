/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import java.lang.reflect.UndeclaredThrowableException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

/**
 * A SASL client factory which establishes a {@link Subject} for the duration of the authentication request.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SubjectSaslClientFactory extends AbstractDelegatingSaslClientFactory {

    private final Subject subject;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate client factory
     * @param subject the subject to use, or {@code null} if the subject should be explicitly set to {@code null}
     */
    public SubjectSaslClientFactory(final SaslClientFactory delegate, final Subject subject) {
        super(delegate);
        this.subject = subject;
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        try {
            return new SubjectSaslClient(Subject.doAs(subject, (PrivilegedExceptionAction<SaslClient>) () -> super.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh)), subject);
        } catch (PrivilegedActionException e) {
            try {
                throw e.getCause();
            } catch (SaslException | RuntimeException | Error e2) {
                throw e2;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
    }
}
