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

import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.Callable;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.LongFunction;
import java.util.function.ObjIntConsumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.wildfly.common.function.ExceptionBiConsumer;
import org.wildfly.common.function.ExceptionBiFunction;
import org.wildfly.common.function.ExceptionBiPredicate;
import org.wildfly.common.function.ExceptionConsumer;
import org.wildfly.common.function.ExceptionFunction;
import org.wildfly.common.function.ExceptionIntFunction;
import org.wildfly.common.function.ExceptionLongFunction;
import org.wildfly.common.function.ExceptionObjIntConsumer;
import org.wildfly.common.function.ExceptionPredicate;
import org.wildfly.common.function.ExceptionSupplier;

/**
 * An identity configuration which can be applied on a scoped basis.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface Scoped {
    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     */
    default void runAs(Runnable action) {
        if (action == null) return;
        runAsConsumer(Runnable::run, action);
    }

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     * @throws Exception if the action fails
     */
    default <T> T runAs(Callable<T> action) throws Exception {
        if (action == null) return null;
        return runAsFunctionEx(Callable::call, action);
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <R> the action return type
     * @param <T> the action parameter type
     * @return the action result (may be {@code null})
     */
    default <T, R> R runAsFunction(Function<T, R> action, T parameter) {
        if (action == null) return null;
        return runAsFunction(Function::apply, action, parameter);
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <R> the action return type
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     * @return the action result (may be {@code null})
     */
    <T, U, R> R runAsFunction(BiFunction<T, U, R> action, T parameter1, U parameter2);

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action parameter type
     */
    default <T> void runAsConsumer(Consumer<T> action, T parameter) {
        if (action == null) return;
        runAsConsumer(Consumer::accept, action, parameter);
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     */
    <T, U> void runAsConsumer(BiConsumer<T, U> action, T parameter1, U parameter2);

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <T> the action first parameter type
     */
    <T> void runAsObjIntConsumer(ObjIntConsumer<T> action, T parameter1, int parameter2);

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @return the action result (may be {@code null})
     */
    default <T> T runAsSupplier(Supplier<T> action) {
        if (action == null) return null;
        return runAsFunction(Supplier::get, action);
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <R> the action return type
     * @param <T> the action parameter type
     * @param <E> the action exception type
     * @return the action result (may be {@code null})
     * @throws E if the action throws this exception
     */
    default <T, R, E extends Exception> R runAsFunctionEx(ExceptionFunction<T, R, E> action, T parameter) throws E {
        if (action == null) return null;
        return runAsFunctionEx(ExceptionFunction::apply, action, parameter);
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <R> the action return type
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     * @param <E> the action exception type
     * @return the action result (may be {@code null})
     * @throws E if the action throws this exception
     */
    <T, U, R, E extends Exception> R runAsFunctionEx(ExceptionBiFunction<T, U, R, E> action, T parameter1, U parameter2) throws E;

    /**
     * Run an action under this identity.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run
     * @param <T> the action parameter type
     * @param <E> the action exception type
     * @throws E if the action throws this exception
     */
    default <T, E extends Exception> void runAsConsumerEx(ExceptionConsumer<T, E> action, T parameter) throws E {
        if (action == null) return;
        runAsConsumerEx(ExceptionConsumer::accept, action, parameter);
    }

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <T> the action first parameter type
     * @param <U> the action second parameter type
     * @param <E> the action exception type
     * @throws E if the action throws this exception
     */
    <T, U, E extends Exception> void runAsConsumerEx(ExceptionBiConsumer<T, U, E> action, T parameter1, U parameter2) throws E;

    /**
     * Run an action under this identity.
     *
     * @param parameter1 the first parameter to pass to the action
     * @param parameter2 the second parameter to pass to the action
     * @param action the action to run
     * @param <T> the action first parameter type
     * @param <E> the action exception type
     * @throws E if the action throws this exception
     */
    <T, E extends Exception> void runAsObjIntConsumerEx(ExceptionObjIntConsumer<T, E> action, T parameter1, int parameter2) throws E;

    /**
     * Run an action under this identity.
     *
     * @param action the action to run
     * @param <T> the action return type
     * @param <E> the action exception type
     * @return the action result (may be {@code null})
     * @throws E if the action throws this exception
     */
    default <T, E extends Exception> T runAsSupplierEx(ExceptionSupplier<T, E> action) throws E {
        if (action == null) return null;
        return runAsFunctionEx(ExceptionSupplier::get, action);
    }

    /**
     * Run an action under this identity.
     *
     * @param action the task to run (must not be {@code null})
     * @param <R> the return value type
     * @return the action return value
     */
    default <R> R runAsAction(PrivilegedAction<R> action) {
        if (action == null) return null;
        return runAsFunction(PrivilegedAction::run, action);
    }

    /**
     * Run an action under this identity.
     *
     * @param action the task to run (must not be {@code null})
     * @param <R> the return value type
     * @return the action return value
     * @throws PrivilegedActionException if the action fails with an exception
     */
    default <R> R runAsExceptionAction(PrivilegedExceptionAction<R> action) throws PrivilegedActionException {
        if (action == null) return null;
        try {
            return runAsFunctionEx(PrivilegedExceptionAction::run, action);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    /**
     * Run an action under this identity.
     *
     * @param predicate the task to run (must not be {@code null})
     * @param param1 the first parameter to pass to the task
     * @param param2 the second parameter to pass to the task
     * @param <T> the first parameter type
     * @param <U> the second parameter type
     * @return the action return value
     * @throws UnsupportedOperationException if this operation is not implemented
     */
    default <T, U> boolean runAsBiPredicate(BiPredicate<T, U> predicate, T param1, U param2) {
        throw new UnsupportedOperationException();
    }

    /**
     * Run an action under this identity.
     *
     * @param predicate the task to run (must not be {@code null})
     * @param param1 the first parameter to pass to the task
     * @param param2 the second parameter to pass to the task
     * @param <T> the first parameter type
     * @param <U> the second parameter type
     * @param <E> the exception type
     * @return the action return value
     * @throws E if an exception occurs in the task
     * @throws UnsupportedOperationException if this operation is not implemented
     */
    default <T, U, E extends Exception> boolean runAsExBiPredicate(ExceptionBiPredicate<T, U, E> predicate, T param1, U param2) throws E {
        throw new UnsupportedOperationException();
    }

    /**
     * Run an action under this identity.
     *
     * @param predicate the task to run (must not be {@code null})
     * @param param the parameter to pass to the task
     * @param <T> the first parameter type
     * @return the action return value
     */
    default <T> boolean runAsPredicate(Predicate<T> predicate, T param) {
        if (predicate == null) return false;
        return runAsBiPredicate(Predicate::test, predicate, param);
    }

    /**
     * Run an action under this identity.
     *
     * @param predicate the task to run (must not be {@code null})
     * @param param the parameter to pass to the task
     * @param <T> the first parameter type
     * @param <E> the exception type
     * @return the action return value
     * @throws E if an exception occurs in the task
     */
    default <T, E extends Exception> boolean runAsExPredicate(ExceptionPredicate<T, E> predicate, T param) throws E {
        if (predicate == null) return false;
        return runAsExBiPredicate(ExceptionPredicate::test, predicate, param);
    }

    /**
     * Run an action under this identity.
     *
     * @param action the task to run (must not be {@code null})
     * @param value the parameter to pass to the task
     * @param <T> the return value type
     * @return the action return value
     */
    default <T> T runAsIntFunction(IntFunction<T> action, int value) {
        if (action == null) return null;
        return runAsFunction(IntFunction::apply, action, value);
    }

    /**
     * Run an action under this identity.
     *
     * @param action the task to run (must not be {@code null})
     * @param value the parameter to pass to the task
     * @param <T> the return value type
     * @param <E> the exception type
     * @return the action return value
     * @throws E if an exception occurs in the task
     */
    default <T, E extends Exception> T runAsExIntFunction(ExceptionIntFunction<T, E> action, int value) throws E {
        if (action == null) return null;
        return runAsFunctionEx(ExceptionIntFunction::apply, action, value);
    }

    /**
     * Run an action under this identity.
     *
     * @param action the task to run (must not be {@code null})
     * @param value the parameter to pass to the task
     * @param <T> the return value type
     * @return the action return value
     */
    default <T> T runAsLongFunction(LongFunction<T> action, long value) {
        if (action == null) return null;
        return runAsFunction(LongFunction::apply, action, value);
    }

    /**
     * Run an action under this identity.
     *
     * @param action the task to run (must not be {@code null})
     * @param value the parameter to pass to the task
     * @param <T> the return value type
     * @param <E> the exception type
     * @return the action return value
     * @throws E if an exception occurs in the task
     */
    default <T, E extends Exception> T runAsExLongFunction(ExceptionLongFunction<T, E> action, long value) throws E {
        if (action == null) return null;
        return runAsFunctionEx(ExceptionLongFunction::apply, action, value);
    }
}
