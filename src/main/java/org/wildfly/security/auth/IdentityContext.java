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

package org.wildfly.security.auth;

import java.net.URI;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class IdentityContext {

    private static final ThreadLocal<IdentityContext> currentIdentityContext = new ThreadLocal<IdentityContext>() {
        protected IdentityContext initialValue() {
            return DefaultIdentityContextProvider.DEFAULT;
        }
    };

    static class Rule {
        private final MatchRule matchRule;
        private final AuthenticationConfiguration configuration;

        Rule(final MatchRule matchRule, final AuthenticationConfiguration configuration) {
            this.matchRule = matchRule;
            this.configuration = configuration;
        }
    }

    private final Rule[] rules;

    private static final Rule[] NO_RULES = new Rule[0];

    static final IdentityContext EMPTY = new IdentityContext();

    private IdentityContext() {
        this(NO_RULES, false);
    }

    IdentityContext(final Rule[] rules, boolean clone) {
        if (clone) {
            this.rules = rules.clone();
        } else {
            this.rules = rules;
        }
    }

    /**
     * Get a new, empty identity context.
     *
     * @return the new identity context
     */
    public static IdentityContext empty() {
        return EMPTY;
    }

    /**
     * Get the current thread's captured identity context.
     *
     * @return the current thread's captured identity context
     */
    public static IdentityContext captureCurrent() {
        return currentIdentityContext.get();
    }

    /**
     * Parse an identity context from XML.
     *
     * @param reader the XML stream reader to use
     *
     * @return the identity context
     *
     * @throws XMLStreamException if an XML read error has occurred
     */
    static IdentityContext fromXML(XMLStreamReader reader) throws XMLStreamException {
        return null;
    }

    /**
     * Get a new identity context which is the same as this one, but which includes the given rule and configuration at
     * the end of its list.
     *
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined identity context
     */
    public IdentityContext with(MatchRule rule, AuthenticationConfiguration configuration) {
        if (configuration == null || rule == null) return this;
        final Rule[] rules = this.rules;
        final int length = rules.length;
        if (length == 0) {
            return new IdentityContext(new Rule[] { new Rule(rule, configuration) }, false);
        } else {
            final Rule[] copy = Arrays.copyOf(rules, length + 1);
            copy[length] = new Rule(rule, configuration);
            return new IdentityContext(copy, false);
        }
    }

    /**
     * Get a new identity context which is the same as this one, but which includes the rules and configurations of the
     * given context at the end of its list.
     *
     * @param other the other identity context
     * @return the combined identity context
     */
    public IdentityContext with(IdentityContext other) {
        if (other == null) return this;
        final Rule[] rules = this.rules;
        final Rule[] otherRules = other.rules;
        final int length = rules.length;
        final int otherLength = otherRules.length;
        if (length == 0) {
            return other;
        } else if (otherLength == 0) {
            return this;
        }
        final Rule[] copy = Arrays.copyOf(rules, length + otherLength);
        System.arraycopy(otherRules, 0, copy, length, otherLength);
        return new IdentityContext(copy, false);
    }

    /**
     * Get a new identity context which is the same as this one, but which includes the given rule and configuration
     * inserted at the position of its list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined identity context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public IdentityContext with(int idx, MatchRule rule, AuthenticationConfiguration configuration) throws IndexOutOfBoundsException {
        if (configuration == null || rule == null) return this;
        final Rule[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx > length) {
            throw new IndexOutOfBoundsException();
        }
        if (length == 0) {
            return new IdentityContext(new Rule[] { new Rule(rule, configuration) }, false);
        } else {
            final Rule[] copy = Arrays.copyOf(rules, length + 1);
            System.arraycopy(copy, idx, copy, idx + 1, length - idx);
            copy[idx] = new Rule(rule, configuration);
            return new IdentityContext(copy, false);
        }
    }

    /**
     * Get a new identity context which is the same as this one, but which replaces the rule and configuration at the given
     * index with the given rule and configuration.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined identity context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public IdentityContext replacing(int idx, MatchRule rule, AuthenticationConfiguration configuration) throws IndexOutOfBoundsException {
        if (configuration == null || rule == null) return this;
        final Rule[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx > length) {
            throw new IndexOutOfBoundsException();
        }
        final Rule[] copy = rules.clone();
        copy[idx] = new Rule(rule, configuration);
        return new IdentityContext(copy, false);
    }

    /**
     * Get a new identity context which is the same as this one, but which includes the rules and configurations of the
     * given context inserted at the position of this context's list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param other the other identity context
     * @return the combined identity context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public IdentityContext with(int idx, IdentityContext other) throws IndexOutOfBoundsException {
        final Rule[] rules = this.rules;
        final int length = rules.length;
        if (idx == length) return with(other);
        if (idx == 0) return other.with(this);
        if (idx < 0 || idx > length) {
            throw new IndexOutOfBoundsException();
        }
        if (other == null) return this;
        final Rule[] otherRules = other.rules;
        final int otherLength = otherRules.length;
        if (otherLength == 0) return this;
        if (length == 0) {
            return other;
        } else {
            final Rule[] copy = Arrays.copyOf(rules, length + otherLength);
            System.arraycopy(copy, idx, copy, idx + otherLength, length - idx);
            System.arraycopy(otherRules, 0, copy, idx, otherLength);
            return new IdentityContext(copy, false);
        }
    }

    /**
     * Get a new identity context which is the same as this one, but without the rule and configuration at the index
     * indicated by the {@code idx} parameter.
     *
     * @param idx the index at which removal should be done
     * @return the modified identity context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public IdentityContext without(int idx) throws IndexOutOfBoundsException {
        final Rule[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx >= length) {
            throw new IndexOutOfBoundsException();
        }
        if (length == 1) {
            assert idx == 0;
            return EMPTY;
        }
        final Rule[] copy;
        if (idx == 0) {
            copy = Arrays.copyOfRange(rules, 1, length - 1);
        } else if (idx == length - 1) {
            copy = Arrays.copyOfRange(rules, 0, length - 1);
        } else {
            copy = Arrays.copyOfRange(rules, 0, length - 1);
            System.arraycopy(rules, idx + 1, copy, idx, length - idx - 1);
        }
        return new IdentityContext(copy, false);
    }

    int ruleMatching(URI uri) {
        for (int i = 0, rulesLength = rules.length; i < rulesLength; i++) {
            if (rules[i].matchRule.matches(uri)) return i;
        }
        return -1;
    }

    MatchRule getMatchRule(int idx) {
        final Rule[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx >= length) {
            throw new IndexOutOfBoundsException();
        }
        return rules[idx].matchRule;
    }

    AuthenticationConfiguration getAuthenticationConfiguration(int idx) {
        final Rule[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx >= length) {
            throw new IndexOutOfBoundsException();
        }
        return rules[idx].configuration;
    }

    /**
     * Run a privileged action with this identity context associated for the duration of the task.
     *
     * @param action the action to run under association
     * @param <T> the action return type
     * @return the action return value
     */
    public <T> T run(PrivilegedAction<T> action) {
        if (action == null) {
            throw new NullPointerException("action is null");
        }
        final IdentityContext oldSubj = currentIdentityContext.get();
        if (oldSubj == this) {
            return action.run();
        }
        currentIdentityContext.set(this);
        try {
            return action.run();
        } finally {
            currentIdentityContext.set(oldSubj);
        }
    }

    /**
     * Run a privileged action with this identity context associated for the duration of the task.
     *
     * @param action the action to run under association
     * @param <T> the action return type
     * @return the action return value
     * @throws PrivilegedActionException if the action throws an exception
     */
    public <T> T run(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        if (action == null) {
            throw new NullPointerException("action is null");
        }
        final IdentityContext oldSubj = currentIdentityContext.get();
        if (oldSubj == this) {
            try {
                return action.run();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        currentIdentityContext.set(this);
        try {
            try {
                return action.run();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        } finally {
            currentIdentityContext.set(oldSubj);
        }
    }

    /**
     * Run a privileged action with this identity context associated for the duration of the task.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run under association
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action return value
     */
    public <T, P> T run(P parameter, ParametricPrivilegedAction<T, P> action) {
        if (action == null) {
            throw new NullPointerException("action is null");
        }
        final IdentityContext oldSubj = currentIdentityContext.get();
        if (oldSubj == this) {
            return action.run(parameter);
        }
        currentIdentityContext.set(this);
        try {
            return action.run(parameter);
        } finally {
            currentIdentityContext.set(oldSubj);
        }
    }

    /**
     * Run a privileged action with this identity context associated for the duration of the task.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run under association
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action return value
     * @throws PrivilegedActionException if the action throws an exception
     */
    public <T, P> T run(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        if (action == null) {
            throw new NullPointerException("action is null");
        }
        final IdentityContext oldSubj = currentIdentityContext.get();
        if (oldSubj == this) {
            try {
                return action.run(parameter);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        }
        currentIdentityContext.set(this);
        try {
            try {
                return action.run(parameter);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new PrivilegedActionException(e);
            }
        } finally {
            currentIdentityContext.set(oldSubj);
        }
    }
}
