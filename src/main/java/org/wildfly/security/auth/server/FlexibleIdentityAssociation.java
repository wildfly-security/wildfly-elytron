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

package org.wildfly.security.auth.server;

import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.ObjIntConsumer;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.common.function.ExceptionBiConsumer;
import org.wildfly.common.function.ExceptionBiFunction;
import org.wildfly.common.function.ExceptionObjIntConsumer;
import org.wildfly.security._private.ElytronMessages;

/**
 * A flexible identity association which can have its current identity modified.  Modifying the identity association
 * will affect the current identity of any thread which is currently executing within the scope of this association.
 *
 * @see SecurityIdentity#createFlexibleAssociation
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class FlexibleIdentityAssociation implements Scoped, Supplier<SecurityIdentity> {
    private final SecurityDomain securityDomain;
    private volatile SecurityIdentity securityIdentity;

    FlexibleIdentityAssociation(final SecurityDomain securityDomain, final SecurityIdentity securityIdentity) {
        assert securityIdentity != null && securityDomain == securityIdentity.getSecurityDomain();
        this.securityDomain = securityDomain;
        this.securityIdentity = securityIdentity;
    }

    /**
     * Set the current associated identity.
     *
     * @param securityIdentity the current associated identity (must not be {@code null})
     */
    public void setIdentity(SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);
        if (securityIdentity.getSecurityDomain() != securityDomain) {
            throw ElytronMessages.log.securityDomainMismatch();
        }
        this.securityIdentity = securityIdentity;
    }

    /**
     * Get the current associated identity.
     *
     * @return the current associated identity (not {@code null})
     */
    public SecurityIdentity get() {
        return securityIdentity;
    }

    public <T, U, R> R runAsFunction(final BiFunction<T, U, R> action, final T parameter1, final U parameter2) {
        final Supplier<SecurityIdentity> old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return action.apply(parameter1, parameter2);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    public <T, U> void runAsConsumer(final BiConsumer<T, U> action, final T parameter1, final U parameter2) {
        final Supplier<SecurityIdentity> old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            action.accept(parameter1, parameter2);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    public <T> void runAsObjIntConsumer(final ObjIntConsumer<T> action, final T parameter1, final int parameter2) {
        final Supplier<SecurityIdentity> old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            action.accept(parameter1, parameter2);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    public <T, U, R, E extends Exception> R runAsFunctionEx(final ExceptionBiFunction<T, U, R, E> action, final T parameter1, final U parameter2) throws E {
        final Supplier<SecurityIdentity> old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            return action.apply(parameter1, parameter2);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    public <T, U, E extends Exception> void runAsConsumerEx(final ExceptionBiConsumer<T, U, E> action, final T parameter1, final U parameter2) throws E {
        final Supplier<SecurityIdentity> old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            action.accept(parameter1, parameter2);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }

    public <T, E extends Exception> void runAsObjIntConsumerEx(final ExceptionObjIntConsumer<T, E> action, final T parameter1, final int parameter2) throws E {
        final Supplier<SecurityIdentity> old = securityDomain.getAndSetCurrentSecurityIdentity(this);
        try {
            action.accept(parameter1, parameter2);
        } finally {
            securityDomain.setCurrentSecurityIdentity(old);
        }
    }
}
