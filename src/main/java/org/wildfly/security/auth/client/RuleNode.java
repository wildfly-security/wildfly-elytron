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

package org.wildfly.security.auth.client;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class RuleNode<T> {
    final RuleNode<T> next;
    final MatchRule rule;
    final T configuration;

    RuleNode(final RuleNode<T> next, final MatchRule rule, final T configuration) {
        this.next = next;
        this.rule = rule;
        this.configuration = configuration;
    }

    RuleNode<T> getNext() {
        return next;
    }

    MatchRule getRule() {
        return rule;
    }

    T getConfiguration() {
        return configuration;
    }

    RuleNode<T> without(int idx) {
        if (idx < 0) {
            throw new IndexOutOfBoundsException();
        }
        final RuleNode<T> next = this.next;
        if (idx == 0) {
            return next;
        }
        if (next == null) {
            throw new IndexOutOfBoundsException();
        }
        return new RuleNode<T>(next.without(idx - 1), rule, configuration);
    }

    RuleNode<T> with(MatchRule rule, T configuration, int idx) {
        if (idx < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (idx == 0) {
            return new RuleNode<T>(this, rule, configuration);
        }
        final RuleNode<T> next = this.next;
        if (next == null) {
            throw new IndexOutOfBoundsException();
        }
        return new RuleNode<T>(next.with(rule, configuration, idx - 1), this.rule, this.configuration);
    }

    RuleNode<T> with(final MatchRule rule, final T configuration) {
        return withAll(new RuleNode<T>(null, rule, configuration));
    }

    RuleNode<T> withAll(RuleNode<T> other) {
        final RuleNode<T> next = this.next;
        if (next == null) {
            return new RuleNode<T>(other, rule, configuration);
        } else {
            return new RuleNode<T>(next.withAll(other), rule, configuration);
        }
    }

    RuleNode<T> withAll(final RuleNode<T> authRules, final int idx) {
        if (idx < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (idx == 0) {
            return authRules.withAll(this);
        }
        final RuleNode<T> next = this.next;
        if (next == null) {
            throw new IndexOutOfBoundsException();
        }
        return new RuleNode<T>(next.withAll(authRules, idx - 1), rule, configuration);
    }

    RuleNode<T> replacing(final MatchRule rule, final T configuration, final int idx) {
        if (idx < 0) {
            throw new IndexOutOfBoundsException();
        }
        final RuleNode<T> next = this.next;
        if (idx == 0) {
            return new RuleNode<T>(next, rule, configuration);
        }
        if (next == null) {
            throw new IndexOutOfBoundsException();
        }
        return new RuleNode<T>(next.with(rule, configuration, idx - 1), rule, configuration);
    }
}
