/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import static java.security.AccessController.doPrivileged;

import java.net.URI;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.wildfly.common.context.ContextManager;
import org.wildfly.common.context.Contextual;
import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.Version;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationContext implements Contextual<AuthenticationContext> {

    private static final ContextManager<AuthenticationContext> CONTEXT_MANAGER = new ContextManager<AuthenticationContext>(AuthenticationContext.class);

    private static final Supplier<AuthenticationContext> SUPPLIER = doPrivileged((PrivilegedAction<Supplier<AuthenticationContext>>) CONTEXT_MANAGER::getPrivilegedSupplier);

    static {
        Version.getVersion();
        CONTEXT_MANAGER.setGlobalDefaultSupplier(() -> DefaultAuthenticationContextProvider.DEFAULT);
    }

    final RuleNode<AuthenticationConfiguration> authRules;
    final RuleNode<SecurityFactory<SSLContext>> sslRules;

    static final AuthenticationContext EMPTY = new AuthenticationContext();

    private AuthenticationContext() {
        this(null, null);
    }

    AuthenticationContext(final RuleNode<AuthenticationConfiguration> authRules, final RuleNode<SecurityFactory<SSLContext>> sslRules) {
        this.authRules = authRules;
        this.sslRules = sslRules;
    }

    /**
     * Get a new, empty authentication context.
     *
     * @return the new authentication context
     */
    public static AuthenticationContext empty() {
        return EMPTY;
    }

    /**
     * Get the current thread's captured authentication context.
     *
     * @return the current thread's captured authentication context
     */
    public static AuthenticationContext captureCurrent() {
        return SUPPLIER.get();
    }

    private static <T> RuleNode<T> with(RuleNode<T> node, MatchRule rule, T item) {
        return node == null ? new RuleNode<T>(null, rule, item) : node.with(rule, item);
    }

    private static <T> RuleNode<T> with(RuleNode<T> node, MatchRule rule, T item, int idx) {
        return node == null ? new RuleNode<T>(null, rule, item) : node.with(rule, item, idx);
    }

    private static <T> RuleNode<T> replacing(RuleNode<T> node, MatchRule rule, T item, int idx) {
        return node == null ? new RuleNode<T>(null, rule, item) : node.replacing(rule, item, idx);
    }

    private static <T> RuleNode<T> withAll(RuleNode<T> node, RuleNode<T> otherNode) {
        return node == null ? otherNode : otherNode == null ? node : node.withAll(otherNode);
    }

    private static <T> RuleNode<T> withAll(RuleNode<T> node, RuleNode<T> otherNode, int idx) {
        return node == null ? otherNode : otherNode == null ? node : node.withAll(otherNode, idx);
    }

    private static <T> RuleNode<T> without(RuleNode<T> node, int idx) {
        return node == null ? null : node.without(idx);
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the given rule and configuration at
     * the end of its list.
     *
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined authentication context
     */
    public AuthenticationContext with(MatchRule rule, AuthenticationConfiguration configuration) {
        if (configuration == null || rule == null) return this;
        return new AuthenticationContext(with(authRules, rule, configuration), sslRules);
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the given rule and SSL context at
     * the end of its SSL context list.
     *
     * @param rule the rule to match
     * @param sslContext the SSL context to select when the rule matches
     * @return the combined authentication context
     */
    public AuthenticationContext withSsl(MatchRule rule, SecurityFactory<SSLContext> sslContext) {
        if (sslContext == null || rule == null) return this;
        return new AuthenticationContext(authRules, with(sslRules, rule, sslContext));
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the rules and configurations of the
     * given context at the end of its list.
     *
     * @param other the other authentication context
     * @return the combined authentication context
     */
    public AuthenticationContext with(AuthenticationContext other) {
        if (other == null) return this;
        return new AuthenticationContext(withAll(authRules, other.authRules), withAll(sslRules, other.sslRules));
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the given rule and configuration
     * inserted at the position of its list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext with(int idx, MatchRule rule, AuthenticationConfiguration configuration) throws IndexOutOfBoundsException {
        if (configuration == null || rule == null) return this;
        return new AuthenticationContext(with(authRules, rule, configuration, idx), sslRules);
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the given rule and SSL context
     * inserted at the position of its list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param sslContext the SSL context to select when the rule matches
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext withSsl(int idx, MatchRule rule, SecurityFactory<SSLContext> sslContext) throws IndexOutOfBoundsException {
        if (sslContext == null || rule == null) return this;
        return new AuthenticationContext(authRules, with(sslRules, rule, sslContext, idx));
    }

    /**
     * Get a new authentication context which is the same as this one, but which replaces the rule and configuration at the given
     * index with the given rule and configuration.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext replacing(int idx, MatchRule rule, AuthenticationConfiguration configuration) throws IndexOutOfBoundsException {
        if (configuration == null || rule == null) return this;
        return new AuthenticationContext(replacing(authRules, rule, configuration, idx), sslRules);
    }

    /**
     * Get a new authentication context which is the same as this one, but which replaces the rule and SSL context at the given
     * index with the given rule and SSL context.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param sslContext the SSL context to select when the rule matches
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext replacingSslContext(int idx, MatchRule rule, SecurityFactory<SSLContext> sslContext) throws IndexOutOfBoundsException {
        if (sslContext == null || rule == null) return this;
        return new AuthenticationContext(authRules, replacing(sslRules, rule, sslContext, idx));
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the rules and configurations of the
     * given context inserted at the position of this context's list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param other the other authentication context
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext with(int idx, AuthenticationContext other) throws IndexOutOfBoundsException {
        if (other == null) return this;
        return new AuthenticationContext(withAll(authRules, other.authRules, idx), sslRules);
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the rules and SSL contexts of the
     * given context inserted at the position of this context's list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param other the other authentication context
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext withSsl(int idx, AuthenticationContext other) throws IndexOutOfBoundsException {
        if (other == null) return this;
        return new AuthenticationContext(authRules, withAll(sslRules, other.sslRules, idx));
    }

    /**
     * Get a new authentication context which is the same as this one, but without the rule and configuration at the index
     * indicated by the {@code idx} parameter.
     *
     * @param idx the index at which removal should be done
     * @return the modified authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext without(int idx) throws IndexOutOfBoundsException {
        return new AuthenticationContext(without(authRules, idx), sslRules);
    }

    /**
     * Get a new authentication context which is the same as this one, but without the rule and configuration at the index
     * indicated by the {@code idx} parameter.
     *
     * @param idx the index at which removal should be done
     * @return the modified authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext withoutSsl(int idx) throws IndexOutOfBoundsException {
        return new AuthenticationContext(authRules, without(sslRules, idx));
    }

    RuleNode<AuthenticationConfiguration> authRuleMatching(URI uri) {
        RuleNode<AuthenticationConfiguration> node = this.authRules;
        while (node != null) {
            if (node.getRule().matches(uri)) return node;
            node = node.getNext();
        }
        return null;
    }

    RuleNode<SecurityFactory<SSLContext>> sslRuleMatching(URI uri) {
        RuleNode<SecurityFactory<SSLContext>> node = this.sslRules;
        while (node != null) {
            if (node.getRule().matches(uri)) return node;
            node = node.getNext();
        }
        return null;
    }

    /**
     * Run a privileged action with this authentication context associated for the duration of the task.
     *
     * @param action the action to run under association
     * @param <T> the action return type
     * @return the action return value
     */
    public <T> T run(PrivilegedAction<T> action) {
        return runAction(action);
    }

    /**
     * Run a privileged action with this authentication context associated for the duration of the task.
     *
     * @param action the action to run under association
     * @param <T> the action return type
     * @return the action return value
     * @throws PrivilegedActionException if the action throws an exception
     */
    public <T> T run(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        return runExceptionAction(action);
    }

    /**
     * Run a privileged action with this authentication context associated for the duration of the task.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run under association
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action return value
     */
    public <T, P> T run(P parameter, ParametricPrivilegedAction<T, P> action) {
        return runFunction(action, parameter);
    }

    /**
     * Run a privileged action with this authentication context associated for the duration of the task.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run under association
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action return value
     * @throws PrivilegedActionException if the action throws an exception
     */
    public <T, P> T run(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        try {
            return runExFunction(action, parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    public ContextManager<AuthenticationContext> getInstanceContextManager() {
        return getContextManager();
    }

    /**
     * Get the context manager for authentication contexts.
     *
     * @return the context manager for authentication contexts (not {@code null})
     */
    public static ContextManager<AuthenticationContext> getContextManager() {
        return CONTEXT_MANAGER;
    }
}
