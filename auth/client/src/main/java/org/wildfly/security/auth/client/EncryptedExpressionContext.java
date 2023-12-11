/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

import org.wildfly.common.context.ContextManager;
import org.wildfly.common.context.Contextual;
import org.wildfly.security.Version;

import java.security.PrivilegedAction;
import java.util.function.Supplier;

import static java.security.AccessController.doPrivileged;

/**
 * A set of resolvers and credential stores used to handle encrypted expressions.
 *
 * @author <a href="mailto:p.paul@redhat.com">Prarthona Paul</a>
 */
public final class EncryptedExpressionContext implements Contextual<EncryptedExpressionContext>{
    private static final ContextManager<EncryptedExpressionContext> CONTEXT_MANAGER = new ContextManager<EncryptedExpressionContext>(EncryptedExpressionContext.class);

    private static final Supplier<EncryptedExpressionContext> SUPPLIER = doPrivileged((PrivilegedAction<Supplier<EncryptedExpressionContext>>) CONTEXT_MANAGER::getPrivilegedSupplier);

    static {
        Version.getVersion();
        CONTEXT_MANAGER.setGlobalDefaultSupplier(() -> EncryptedExpressionContext.EMPTY);
    }

    final EncryptedExpressionConfig encryptedExpressionConfig = new EncryptedExpressionConfig();

    static final EncryptedExpressionContext EMPTY = new EncryptedExpressionContext();
    final RuleNode<EncryptedExpressionConfig> encryptionRuleNode;

    EncryptedExpressionContext() {
        this(null);
    }

    EncryptedExpressionContext(final RuleNode<EncryptedExpressionConfig> encryptionRuleNode) {
        this.encryptionRuleNode = encryptionRuleNode;
    }

    /**
     * Get a new, empty encrypted expression context.
     *
     * @return the new encrypted expression context.
     */
    public static EncryptedExpressionContext empty() {
        return EMPTY;
    }

    /**
     * Get the current thread's captured authentication context.
     *
     * @return the current thread's captured authentication context
     */
    public static EncryptedExpressionContext captureCurrent() {
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
     * Get a new encrypted expression context which is the same as this one, but which includes the given rule and configuration at
     * the end of its list.
     *
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined encrypted expression context
     */
    public EncryptedExpressionContext with(MatchRule rule, EncryptedExpressionConfig configuration) {
        if (configuration == null || rule == null) return this;
        return new EncryptedExpressionContext(with(encryptionRuleNode, rule, configuration));
    }

    /**
     * Get a new encryptedExpression context which is the same as this one, but which includes the configurations
     * of the given context at the end of its list.
     *
     * @param other the other encryptedExpression context
     * @return the combined encryptedExpression context
     */
    public EncryptedExpressionContext with(EncryptedExpressionContext other) {
        if (other == null) return this;
        return new EncryptedExpressionContext(withAll(encryptionRuleNode, other.encryptionRuleNode));
    }

    /**
     * Get a new encryptedExpression context which is the same as this one, but which includes the given configuration
     * inserted at the position of its list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined encryptedExpression context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public EncryptedExpressionContext with(int idx, MatchRule rule, EncryptedExpressionConfig configuration) throws IndexOutOfBoundsException {
        if (configuration == null || rule == null) return this;
        return new EncryptedExpressionContext(with(encryptionRuleNode, rule, configuration, idx));
    }

    /**
     * Get a new encryptedExpression context which is the same as this one, but which replaces the rule and configuration at the given
     * index with the given rule and configuration.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined encryptedExpression context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public EncryptedExpressionContext replacing(int idx, MatchRule rule, EncryptedExpressionConfig configuration) throws IndexOutOfBoundsException {
        if (configuration == null || rule == null) return this;
        return new EncryptedExpressionContext(replacing(encryptionRuleNode, rule, configuration, idx));
    }

    /**
     * Get a new encryptedExpression context which is the same as this one, but without the rule and configuration at the index
     * indicated by the {@code idx} parameter.
     *
     * @param idx the index at which removal should be done
     * @return the modified encryptedExpression context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public EncryptedExpressionContext without(int idx) throws IndexOutOfBoundsException {
        return new EncryptedExpressionContext(without(encryptionRuleNode, idx));
    }

    /**
     * Run a privileged action with this encrypted expression context associated for the duration of the task.
     *
     * @param action the action to run under association
     * @param <T> the action return type
     * @return the action return value
     */
    public <T> T run(PrivilegedAction<T> action) {
        return runAction(action);
    }

    public ContextManager<EncryptedExpressionContext> getInstanceContextManager() {
        return getContextManager();
    }

    public static ContextManager<EncryptedExpressionContext> getContextManager() {
        return CONTEXT_MANAGER;
    }

}
