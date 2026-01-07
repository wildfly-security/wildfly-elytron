/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.auth.realm;

import static java.lang.String.format;
import static org.junit.Assert.assertEquals;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.event.RealmAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmFailedAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmSuccessfulAuthenticationEvent;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * A high level test case for the {@code BruteForceRealmWrapper}.
*
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BruteForceRealmWrapperTest {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    private static final String USER_TEMPLATE = "user-%d";
    private static final String PASSWORD_TEMPLATE = "password-%d";
    private static final String BAD_PASSWORD = "let-me-in";

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    private static String user(final int no) {
        return format(USER_TEMPLATE, no);
    }

    private static char[] password(final int no) {
        return format(PASSWORD_TEMPLATE, no).toCharArray();
    }

    // We are using in memory realms etc so just initialise for each test.

    /**
     * Original SecurityRealm with no wrapping applied.
     */
    private SecurityRealm rawRealm;

    /**
     * SecurityRealm wrapped with brute force protection.
     *
     * This test case configures max failed attempts = 5
     *
     */
    private SecurityRealm protectedRealm;

    private Map<Object, Runnable> scheduledRunnables;

    @Before
    public void setupTestRealm() throws Exception {
        // Base Realm
        SimpleMapBackedSecurityRealm mapBackedSecurityRealm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> identityMap = new HashMap<>();
        mapBackedSecurityRealm.setIdentityMap(identityMap);
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        for (int i = 1 ; i <= 5 ; i++) {
            ClearPasswordSpec passwordSpec = new ClearPasswordSpec(password(i));

            identityMap.put(user(i), new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(factory.generatePassword(passwordSpec)))));
        }
        rawRealm = mapBackedSecurityRealm;

        scheduledRunnables = new HashMap<>();
        protectedRealm = BruteForceRealmWrapper.create()
            .wrapping(rawRealm)
            .withExecutor(createScheduledExecutorService())
            .setMaxFailedAttempts(5)
            .setLockoutInterval(5)
            .setFailureSessionTimeout(2)
            .wrap(SecurityRealm.class);
    }

    @After
    public void clearTest() {
        protectedRealm = null;
        scheduledRunnables = null;
        rawRealm = null;
    }

    private void clearScheduleRunnables() {
        scheduledRunnables.forEach((k, v) -> v.run());
    }

    private void performAuthentication(final SecurityRealm securityRealm, final int identityNo, final boolean expectExists, final boolean simulateSuccess) throws Exception {
        performAuthentication(securityRealm, identityNo, expectExists, simulateSuccess, simulateSuccess);
    }

    private void performAuthentication(final SecurityRealm securityRealm, final int identityNo, final boolean expectExists, final boolean simulateSuccess, final boolean useGoodPassword) throws Exception {
        NamePrincipal principal = new NamePrincipal(user(identityNo));
        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(principal);

        assertEquals("RealmIdentity.exists()", expectExists, realmIdentity.exists());

        PasswordGuessEvidence passwordGuessEvidence = new PasswordGuessEvidence(useGoodPassword ? password(identityNo) : BAD_PASSWORD.toCharArray());
        assertEquals("RealmIdentity.verifyEvidence()", simulateSuccess, realmIdentity.verifyEvidence(passwordGuessEvidence));

        RealmAuthenticationEvent realmAuthenticationEvent;
        if (simulateSuccess) {
            realmAuthenticationEvent = new RealmSuccessfulAuthenticationEvent(realmIdentity, realmIdentity.getAuthorizationIdentity(), null, passwordGuessEvidence);
        } else {
            realmAuthenticationEvent = new RealmFailedAuthenticationEvent(realmIdentity, null, passwordGuessEvidence);
        }
        securityRealm.handleRealmEvent(realmAuthenticationEvent);
    }

    /**
     * Test that the wrapped realm can be repeatedly called for authentication attempts.
     */
    @Test
    public void testSuccessfulAccess() throws Exception {
        // Test against rawRealm - just to verify our call is correct.
        performAuthentication(rawRealm, 1, true, true);

        // Now make 10 calls against the wrapper to verify success.
        for (int i = 0 ; i < 10 ; i++) {
            performAuthentication(protectedRealm, 1, true, true);
        }

        // No failure sessions should have been created.
        assertEquals("No failure sessions", 0, scheduledRunnables.size());
    }

    /**
     * Test that the required number of failed authentications does disable the identity.
     *
     * Also test the base realm still works - i.e. prove it is brute force wrapping preventing access.
     * Simulate the session expiring and verify authentication works again.
     */
    @Test
    public void testDisabledIdentity() throws Exception {
        // Test against rawRealm - just to verify our call is correct.
        performAuthentication(rawRealm, 2, true, true);

        // Now make 5 bad calls
        for (int i = 0 ; i < 5 ; i++) {
            performAuthentication(protectedRealm, 2, true, false, false);
        }

        // Only one identity is being tested so we should have one session.
        assertEquals("Expected failure session", 1, scheduledRunnables.size());

        // Even though we now use the good password we should be locked out.
        performAuthentication(protectedRealm, 2, true, false, true);

        // Test against rawRealm again - double check it is brute force protection causing the lock out.
        performAuthentication(rawRealm, 2, true, true);

        // Remove all tracking sessions - this simulates a session timeout.
        clearScheduleRunnables();

        // Now it should work again
        performAuthentication(protectedRealm, 2, true, true);
    }

    /**
     * If a user has entered the wrong password multiple times but less than max,
     * verify they can
     */
    @Test
    public void testSuccessAfterAlmostBadAccess() throws Exception {
        // Test against rawRealm - just to verify our call is correct.
        performAuthentication(rawRealm, 3, true, true);

        // Now make 4 bad calls
        for (int i = 0 ; i < 4 ; i++) {
            performAuthentication(protectedRealm, 3, true, false, false);
        }

        // Only one identity is being tested so we should have one session.
        assertEquals("Expected failure session", 1, scheduledRunnables.size());

        // We did not quite reach lockout so this should work.
        performAuthentication(protectedRealm, 3, true, true);

        // No failure sessions should have been created.
        assertEquals("No failure sessions", 0, scheduledRunnables.size());

        // Now make 4 bad calls
        for (int i = 0 ; i < 4 ; i++) {
            performAuthentication(protectedRealm, 3, true, false, false);
        }

        // Only one identity is being tested so we should have one session.
        assertEquals("Expected failure session", 1, scheduledRunnables.size());

        // Although we have now had 8 failed attempts, after 4 we had a successful auth which should have caused a reset.
        performAuthentication(protectedRealm, 3, true, true);

        // No failure sessions should have been created.
        assertEquals("No failure sessions", 0, scheduledRunnables.size());
    }

    /**
     * Where the wrapped realm is able to identify if an identity exists this wrapper should not be
     * creating a tracking session for identities that do not exist.
     */
    @Test
    public void testNonExistantIdentity() throws Exception {
        // Test against rawRealm - just to verify our call is correct.
        performAuthentication(rawRealm, 10, false, false);

        // Now make 5 bad calls
        for (int i = 0 ; i < 5 ; i++) {
            performAuthentication(protectedRealm, 10, false, false);
        }

        // No failure sessions should have been created.
        assertEquals("No failure sessions", 0, scheduledRunnables.size());
    }

    /*
     * As part of a unit test we don't want to be waiting for timeouts in the executor, instead we
     * provide a Proxy to intercept the calls so we can verify the registration and simulate the
     * timeouts.
     */

    private ScheduledExecutorService createScheduledExecutorService() {
        return (ScheduledExecutorService) Proxy.newProxyInstance(BruteForceRealmWrapperTest.class.getClassLoader(),
            new Class[] { ScheduledExecutorService.class }, new ScheduledExecutorInvocationHandler());
    }

    static Method getTargetMethod() {
        try {
            return ScheduledExecutorService.class.getMethod("schedule", Runnable.class, long.class, TimeUnit.class);
        } catch (NoSuchMethodException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private class ScheduledExecutorInvocationHandler implements InvocationHandler {

        final Method TARGET_METHOD = getTargetMethod();

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (TARGET_METHOD.equals(method)) {
                if (args[0] instanceof Runnable) {
                    TestScheduledFuture future = new TestScheduledFuture((p) -> scheduledRunnables.remove(p) != null);
                    scheduledRunnables.put(future, (Runnable)args[0]);

                    return future;
                }

                throw new IllegalArgumentException("Expected Runnable");
            } else {
                return null;
            }
        }
    }

    private static class TestScheduledFuture implements ScheduledFuture {

        private final Function<Object, Boolean> cancel;

        private boolean isCancelled = false;

        public TestScheduledFuture(Function<Object, Boolean> cancel) {
            this.cancel = cancel;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            // Not relevant to test.
            return 0;
        }


        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            return cancel.apply(this);
        }

        @Override
        public Object get() throws InterruptedException, ExecutionException {
            // Not relevant to test.
            return null;
        }

        @Override
        public Object get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            // Not relevant to test.
            return null;
        }

        @Override
        public boolean isCancelled() {
            return isCancelled;
        }

        @Override
        public boolean isDone() {
            // Not relevant to test.
            return false;
        }

        @Override
        public int compareTo(Object o) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'compareTo'");
        }

    }

}
