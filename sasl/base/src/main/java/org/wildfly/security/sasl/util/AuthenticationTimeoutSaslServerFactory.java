/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.sasl._private.ElytronMessages.sasl;

import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * A {@link SaslServerFactory} which adds authentication timeout functionality to a delegate {@code SaslServerFactory}.
 * <p>
 * This {@link SaslServerFactory} must be outside of the {@link AuthenticationCompleteCallbackSaslServerFactory} in the
 * chain of SASL server factories.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class AuthenticationTimeoutSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    /**
     * The default amount of time, in seconds, after which an authentication attempt should time out.
     */
    public static final long DEFAULT_TIMEOUT = 150;

    private final ScheduledExecutorService scheduledExecutorService;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     * @param scheduledExecutorService the scheduled executor to use to handle authentication timeout tasks
     */
    public AuthenticationTimeoutSaslServerFactory(final SaslServerFactory delegate, final ScheduledExecutorService scheduledExecutorService) {
        super(delegate);
        Assert.checkNotNullParam("scheduledExecutorService", scheduledExecutorService);
        this.scheduledExecutorService = scheduledExecutorService;
    }

    @Override
    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final long timeout = getTimeout(props);
        final SaslServer delegateSaslServer = delegate.createSaslServer(mechanism, protocol, serverName, props, cbh);
        return (delegateSaslServer == null) ? null : new DelegatingTimeoutSaslServer(delegateSaslServer, scheduledExecutorService, timeout);
    }

    private long getTimeout(final Map<String, ?> props) {
        final long timeout;
        if (props.containsKey(WildFlySasl.AUTHENTICATION_TIMEOUT)) {
            timeout = Long.parseLong((String) props.get(WildFlySasl.AUTHENTICATION_TIMEOUT));
        } else {
            timeout = DEFAULT_TIMEOUT;
        }
        return timeout;
    }

    private static class DelegatingTimeoutSaslServer extends AbstractDelegatingSaslServer {
        private boolean complete;
        private boolean terminated;
        private ScheduledFuture<Void> timeoutTask;

        DelegatingTimeoutSaslServer(final SaslServer delegate, final ScheduledExecutorService scheduledExecutorService, final long timeout) {
            super(delegate);

            // Schedule a task to terminate the authentication attempt if it takes too long
            timeoutTask = scheduledExecutorService.schedule(() -> {
                synchronized (this) {
                    if (! (isComplete() && ! complete)) {
                        dispose();
                        terminated = true;
                    } else {
                        complete = true;
                    }
                    return null;
                }
            }, timeout, TimeUnit.SECONDS);
        }

        @Override
        public synchronized byte[] evaluateResponse(final byte[] response) throws SaslException {
            if (terminated) {
                throw sasl.mechServerTimedOut().toSaslException();
            }
            try {
                final byte[] challenge = delegate.evaluateResponse(response);
                if (isComplete() && ! complete) {
                    complete = true;
                    cancelTimeoutTask();
                }
                return challenge;
            } catch (SaslException | RuntimeException | Error e) {
                if (isComplete() && ! complete) {
                    complete = true;
                    cancelTimeoutTask();
                }
                throw e;
            }
        }

        @Override
        public synchronized void dispose() throws SaslException {
            cancelTimeoutTask();
            super.dispose();
        }

        private synchronized void cancelTimeoutTask() {
            final ScheduledFuture<Void> task = timeoutTask;
            timeoutTask = null;
            if (task != null) {
                task.cancel(true);
            }
        }
    }
}
