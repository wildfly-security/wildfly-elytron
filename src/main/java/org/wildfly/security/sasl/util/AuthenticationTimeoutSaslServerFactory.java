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

import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

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

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate {@code SaslServerFactory}
     */
    public AuthenticationTimeoutSaslServerFactory(final SaslServerFactory delegate) {
        super(delegate);
    }

    @Override
    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final long timeout;
        if (props.containsKey(WildFlySasl.AUTHENTICATION_TIMEOUT)) {
            timeout = Long.parseLong((String) props.get(WildFlySasl.AUTHENTICATION_TIMEOUT));
        } else {
            timeout = DEFAULT_TIMEOUT;
        }

        final SaslServer delegateSaslServer = delegate.createSaslServer(mechanism, protocol, serverName, props, cbh);
        return (delegateSaslServer == null) ? null : new DelegatingTimeoutSaslServer(delegateSaslServer, timeout);
    }

    private static class DelegatingTimeoutSaslServer extends AbstractDelegatingSaslServer {
        private final AtomicBoolean complete = new AtomicBoolean();
        private volatile ScheduledThreadPoolExecutor executor;
        private volatile ScheduledFuture<Void> timeoutTask;

        DelegatingTimeoutSaslServer(final SaslServer delegate, final long timeout) {
            super(delegate);

            // Schedule a task to terminate the authentication attempt if it takes too long
            executor = createExecutor();
            timeoutTask = executor.schedule(() -> {
                if (! (isComplete() && complete.compareAndSet(false, true))) {
                    dispose();
                }
                return null;
            }, timeout, TimeUnit.SECONDS);
        }

        @Override
        public byte[] evaluateResponse(final byte[] response) throws SaslException {
            try {
                final byte[] challenge = delegate.evaluateResponse(response);
                if (isComplete() && complete.compareAndSet(false, true)) {
                    cancelTimeoutTask();
                }
                return challenge;
            } catch (SaslException | RuntimeException | Error e) {
                if (isComplete() && complete.compareAndSet(false, true)) {
                    cancelTimeoutTask();
                }
                throw e;
            }
        }

        @Override
        public void dispose() throws SaslException {
            try {
                super.dispose();
            } finally {
                cancelTimeoutTask();
                ScheduledThreadPoolExecutor stpe = executor;
                executor = null;
                if (stpe != null) {
                    stpe.shutdownNow();
                }
            }
        }

        private ScheduledThreadPoolExecutor createExecutor() {
            ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1);
            executor.setRemoveOnCancelPolicy(true);
            executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
            return executor;
        }

        private void cancelTimeoutTask() {
            final ScheduledFuture<Void> task = timeoutTask;
            timeoutTask = null;
            if (task != null) {
                task.cancel(true);
            }
        }
    }
}
