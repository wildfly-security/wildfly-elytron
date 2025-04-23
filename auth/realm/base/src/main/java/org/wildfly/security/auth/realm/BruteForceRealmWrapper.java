/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.auth.realm;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.realm.ElytronMessages.log;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.auth.server.event.RealmFailedAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmSuccessfulAuthenticationEvent;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * A wrapper around {@code SecurityRealm} instances to add brute force detection
 * for brute force password guessing attacks.
 *
 * After a failed authentication attempt a {@code FailureSession} is created to track
 * the failure count and to coordinate temporarily disabling the identity.
 *
 * This implementation is entirely in memory so will be cleared if the server is
 * reloaded or restarted.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BruteForceRealmWrapper {

    private static final String HANDLE_REALM_EVENT_NAME = "handleRealmEvent";

    private static final Set<Method> GET_IDENTITY_METHODS;
    private static final Method EVENT_HANDLER_METHOD;

    static {
        Set<Method> getIdentityMethods = new HashSet<>();
        // We don't need to scan SecurityRealm as ModificableSecurityRealm extends this.
        for (Method method : ModifiableSecurityRealm.class.getMethods()) {
            if (RealmIdentity.class.isAssignableFrom(method.getReturnType())) {
                getIdentityMethods.add(method);
            }
        }
        GET_IDENTITY_METHODS = Collections.unmodifiableSet(getIdentityMethods);

        try {
            EVENT_HANDLER_METHOD = SecurityRealm.class.getMethod(HANDLE_REALM_EVENT_NAME, RealmEvent.class);
        } catch (NoSuchMethodException | SecurityException e) {
            // This really should not happen so just fail the static initialisation if it does.
            throw new IllegalStateException(e);
        }
    }

    private volatile boolean built = false;

    private ScheduledExecutorService executor;
    private SecurityRealm wrapped;
    private int maxFailedAttempts = 25;
    private int lockoutInterval = 15;
    private int failureSessionTimeout = 60;
    private List<Class<?>> additionalInterfaces = new ArrayList<>();

    /**
     * Create a new instance of {@code BruteForceRealmWrapper} that can be used
     * to wrap a {@code SecurityRealm} instance and provide brute force protection.
     *
     * @return a new instance of {@code BruteForceRealmWrapper}.
     */
    public static BruteForceRealmWrapper create() {
        return new BruteForceRealmWrapper();
    }

     /**
     * Set the {@code ScheduledExecutorService} that will be used for expiring the
     * sessions tracking authentication failures.
     *
     * @param executor the {@code ScheduledExecutorService}
     * @return {@code this} to allow chaining.
     */
    public BruteForceRealmWrapper withExecutor(ScheduledExecutorService executor) {
        assertNotBuilt();
        this.executor = executor;

        return this;
    }

    /**
     * Set the maximum number of consecutive failed login attempts for a specific user
     * before the lockout kicks in for the configured interval.
     *
     * @param maxFailedAttempts - the maximum number of failed attempts before the lockout
     *                          interval kicks in.
     * @return @return {@code this} to allow chaining.
     */
    public BruteForceRealmWrapper setMaxFailedAttempts(final int maxFailedAttempts) {
        assertNotBuilt();
        if (maxFailedAttempts > 0) {
            this.maxFailedAttempts = maxFailedAttempts;
        }

        return this;
    }

    /**
     * After the maximum number of failed authentication attempts the interval in minutes
     * the account will be locked for.
     *
     * Subsequent failed attempts during the lockout period will renew the lockout indefinitely,
     * even if those attempts use the correct credential.
     *
     * @param lockoutInterval the lockout interval in minutes.
     * @return {@code this} to allow chaining.
     */
    public BruteForceRealmWrapper setLockoutInterval(final int lockoutInterval) {
        assertNotBuilt();
        if (lockoutInterval > 0) {
            this.lockoutInterval = lockoutInterval;
        }

        return this;
    }

    /**
     * After a failed authentication attempt how long in minutes to keep the tracking session
     * alive
     *
     * Subsequent failed attempts will renew the timeout.
     *
     * @param failureSessionTimeout the lockout interval in minutes.
     * @return {@code this} to allow chaining.
     */
    public BruteForceRealmWrapper setFailureSessionTimeout(final int failureSessionTimeout) {
        assertNotBuilt();
        if (failureSessionTimeout > 0) {
            this.failureSessionTimeout = failureSessionTimeout;
        }

        return this;
    }

    public BruteForceRealmWrapper addAdditionalInterface(final Class<?> interfaze) {
        assertNotBuilt();
        checkNotNullParam("interfaze", interfaze);
        if (!interfaze.isInterface()) {
            throw log.notAnInterface(interfaze.getName());
        }
        additionalInterfaces.add(interfaze);

        return this;
    }

    /**
     * Set the security realm that is to be wrapped by the wrapper.
     *
     * @param toWrap the security realm that is to be wrapped by the wrapper.
     * @return {@code this} to allow chaining.
     */
    public BruteForceRealmWrapper wrapping(final SecurityRealm toWrap) {
        assertNotBuilt();
        this.wrapped = checkNotNullParam("toWrap", toWrap);

        return this;
    }

    public <S extends SecurityRealm> S wrap(final Class<S> securityRealmType) {
        assertNotBuilt();
        checkNotNullParam("executor", executor);
        checkNotNullParam("wrapped", wrapped);

        ArrayList<Class<?>> proxiedInterfaces = new ArrayList<>();

        // Get the Elytron SecurityRealm interfaces identified.
        if (wrapped instanceof ModifiableSecurityRealm) {
            proxiedInterfaces.add(ModifiableSecurityRealm.class);
        }
        if (wrapped instanceof CacheableSecurityRealm) {
            proxiedInterfaces.add(CacheableSecurityRealm.class);
        }
        if (proxiedInterfaces.isEmpty()) {
            // The prior two extend from this.
            proxiedInterfaces.add(SecurityRealm.class);
        }
        // Iterate the additional interfaces and verify that the wrapped realm does
        // actually support them as we will be just passing calls through.
        for (Class<?> additionalInterface : additionalInterfaces) {
            if (!additionalInterface.isInstance(wrapped)) {
                throw log.doesNotImplementRequiredInterface(wrapped.getClass().getName(), additionalInterface.getName());
            }
            proxiedInterfaces.add(additionalInterface);
        }

        Object proxy = Proxy.newProxyInstance(BruteForceRealmWrapper.class.getClassLoader(),
            proxiedInterfaces.toArray(new Class[proxiedInterfaces.size()]), new RealmWrapper());

        if (!securityRealmType.isInstance(proxy)) {
            throw log.doesNotImplementRequiredInterface(wrapped.getClass().getName(), securityRealmType.getName());
        }

        S response = securityRealmType.cast(proxy);

        built = true;
        return response;
    }

    private void assertNotBuilt() {
        if (built) {
            throw log.bruteForceWrapperAlreadyBuilt();
        }
    }

    private class RealmWrapper implements InvocationHandler {

        private final Map<Principal, FailureSession> failedAttempts = new HashMap<>();

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (EVENT_HANDLER_METHOD.equals(method) && args[0] instanceof RealmEvent) {
                handleRealmEvent((RealmEvent) args[0]);
            } else if (GET_IDENTITY_METHODS.contains(method) && (args[0] instanceof Principal || args[0] instanceof Evidence) ) {
                Principal principal = args[0] instanceof Principal ? (Principal) args[0] : ((Evidence)args[0]).getDecodedPrincipal();
                if (isDisabled(principal)) {
                    Class<?> returnType = method.getReturnType();
                    if (ModifiableRealmIdentity.class.equals(returnType)) {
                        return new DisabledModifiableRealmIdentity(principal);
                    } else if (RealmIdentity.class.equals(returnType)) {
                        return new DisabledRealmIdentity(principal);
                    }
                }
            }

            // If we have reached this point we have not replaced the call to the target realm so can allow it to
            // proceed.
            return method.invoke(wrapped, args);
        }


        private boolean isDisabled(final Principal principal) {
            if (principal == null) {
                return false;
            }

            // If Principal should be blocked.
            //    Return disabled RealmIdentity
            synchronized(failedAttempts) {
                FailureSession session = failedAttempts.get(principal);
                return session != null && session.isDisabled();
                // We don't reset any timers here, that will happen when we receive the decision about
                // the authentication.
            }
        }

        private void invalidate(final Principal principal) {
            synchronized(failedAttempts) {
                failedAttempts.remove(principal);
            }
        }

        private  void handleRealmEvent(RealmEvent event) {
            if (event instanceof RealmFailedAuthenticationEvent) {
                RealmFailedAuthenticationEvent rfae = (RealmFailedAuthenticationEvent) event;
                RealmIdentity identity = rfae.getRealmIdentity();
                final Principal principal = identity != null ? identity.getRealmIdentityPrincipal() : null;

                if (principal != null && exists(identity)) {
                    synchronized (failedAttempts) {
                        FailureSession session = failedAttempts.get(principal);
                        if (session != null) {
                            if (!session.cancelExpiry(true)) {
                                // We hold the lock so if executing we should have been able to interrupt and
                                // prevent it from removing the session.
                                log.tracef("Unable to cancel cleanup for '%s'", principal);
                                return;
                            }
                        } else {
                            session = new FailureSession(() -> invalidate(principal));
                            log.tracef("Beginning tracking of failed authentication attempts for '%s'", principal);
                            failedAttempts.put(principal, session);
                        }
                        int count = session.failAuthentication();
                        if (count >= maxFailedAttempts) {
                            log.tracef("Disabling authentication for '%s'", principal);
                            session.disableForMs(lockoutInterval);
                        }
                        session.scheduleTimeout(failureSessionTimeout);
                    }

                }
            } else if (event instanceof RealmSuccessfulAuthenticationEvent) {
                RealmSuccessfulAuthenticationEvent rsae = (RealmSuccessfulAuthenticationEvent) event;
                RealmIdentity identity = rsae.getRealmIdentity();
                final Principal principal = identity != null ? identity.getRealmIdentityPrincipal() : null;

                if (principal != null) {
                    synchronized (failedAttempts) {
                        FailureSession session = failedAttempts.get(principal);
                        if (session != null) {
                            log.tracef("Successful authentication for previously cached failed authentication '%s'",
                                    principal.getName());
                            // No point interrupting cleanup is likely in progress.
                            if (session.cancelExpiry(false)) {
                                invalidate(principal);
                            }
                        }
                        // If the expiration could not be cancelled it is likely running in parallel
                        // and will remove the session once it obtains the lock.
                    }
                }
            }
        }

    }

    private static boolean exists(RealmIdentity identity) {
        try {
            return identity.exists();
        } catch (RealmUnavailableException e) {
            log.trace("Unable to determine if identity exists", e);
            return false;
        }
    }

    private class FailureSession {
        private final Runnable invalidate;

        private volatile int failedCount = 0;
        private volatile long disableUntil = 0;
        private volatile ScheduledFuture<?> futureCleanup;

        FailureSession(final Runnable invalidate) {
            this.invalidate = invalidate;
        }

        int failAuthentication() {
            return ++failedCount;
        }

        void disableForMs(final long duration) {
            this.disableUntil = System.currentTimeMillis() + duration;
        }

        boolean isDisabled() {
            return System.currentTimeMillis() < disableUntil;
        }

        boolean cancelExpiry(boolean interrupt) {
            return futureCleanup.cancel(interrupt);
        }

        void scheduleTimeout(final long duration) {
            long now = System.currentTimeMillis();
            long disabledDuration = disableUntil - now;
            // Pick the bigger duration incase we disable for longer than the session.
            long scheduleTime = disabledDuration > duration ? disabledDuration : duration;
            futureCleanup = executor.schedule(invalidate::run, scheduleTime, TimeUnit.MILLISECONDS);
        }
    }

    static class DisabledRealmIdentity implements RealmIdentity {

        private final Principal principal;

        DisabledRealmIdentity(final Principal principal) {
            this.principal = principal;
        }

        @Override
        public Principal getRealmIdentityPrincipal() {
            return principal;
        }

        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            return SupportLevel.UNSUPPORTED;
        }

        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            return SupportLevel.UNSUPPORTED;
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            return null;
        }

        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            return false;
        }

        public boolean exists() throws RealmUnavailableException {
            return true;
        }

        @Override
        public String toString() {
            return "DISABLED";
        }
    }

    static class DisabledModifiableRealmIdentity extends DisabledRealmIdentity implements ModifiableRealmIdentity {

        DisabledModifiableRealmIdentity(final Principal principal) {
            super(principal);
        }

        public boolean exists() throws RealmUnavailableException {
            return false;
        }

        public void delete() throws RealmUnavailableException {
            // no operation
        }

        public void create() throws RealmUnavailableException {
            throw log.unableToCreateIdentity();
        }

        public void setCredentials(final Collection<? extends Credential> credentials) throws RealmUnavailableException {
            throw log.noSuchIdentity();
        }

        public void setAttributes(final Attributes attributes) throws RealmUnavailableException {
            throw log.noSuchIdentity();
        }
    }

}
