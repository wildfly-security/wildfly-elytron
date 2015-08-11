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
package org.wildfly.security.http.util;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerExchange;

/**
 * A {@link HttpServerAuthenticationMechanism} with a stored {@link AccessControlContext} that is used for all request
 * processing calls.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class PrivilegedServerMechanism implements HttpServerAuthenticationMechanism {

    private final HttpServerAuthenticationMechanism mechanism;
    private final AccessControlContext accessControlContext;

    PrivilegedServerMechanism(final HttpServerAuthenticationMechanism mechanism, final AccessControlContext accessControlContext) {
        this.mechanism = checkNotNullParam("mechanism", mechanism);
        this.accessControlContext = checkNotNullParam("accessControlContext", accessControlContext);
    }

    @Override
    public String getMechanismName() {
        return mechanism.getMechanismName();
    }

    @Override
    public boolean evaluateRequest(final HttpServerExchange exchange) throws HttpAuthenticationException {
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) () -> {
                return mechanism.evaluateRequest(exchange);
            }, accessControlContext);
        } catch (PrivilegedActionException pae) {
            try {
                throw pae.getCause();
            } catch (HttpAuthenticationException | RuntimeException | Error e) {
                throw e;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
    }

    @Override
    public boolean prepareResponse(HttpServerExchange exchange) throws HttpAuthenticationException {
        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) () -> {
                return mechanism.prepareResponse(exchange);
            }, accessControlContext);
        } catch (PrivilegedActionException pae) {
            try {
                throw pae.getCause();
            } catch (HttpAuthenticationException | RuntimeException | Error e) {
                throw e;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
    }

}
