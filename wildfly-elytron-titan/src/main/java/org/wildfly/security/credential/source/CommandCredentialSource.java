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

package org.wildfly.security.credential.source;

import static org.wildfly.common.Assert.checkNotEmptyParam;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;
import static java.security.AccessController.doPrivileged;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.charset.Charset;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.manager.WildFlySecurityManager;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * A credential source which acquires a credential from the command line.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class CommandCredentialSource implements CredentialSource {

    private static final File NULL_FILE = new File(
            (WildFlySecurityManager.isChecking() ? doPrivileged((PrivilegedAction<String>) () -> System.getProperty("os.name")) : System.getProperty("os.name"))
            .startsWith("Windows") ? "NUL" : "/dev/null");

    private final Function<ProcessBuilder, ProcessBuilder> builderProcessor;
    private final PasswordFactory passwordFactory;
    private final AccessControlContext context;
    private final Charset outputCharset;

    CommandCredentialSource(final Builder builder) throws GeneralSecurityException {
        builderProcessor = builder.builderProcessor;
        this.passwordFactory = builder.passwordFactoryFactory.create();
        context = AccessController.getContext();
        outputCharset = builder.outputCharset;
    }

    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        return credentialType == PasswordCredential.class ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        if (credentialType != PasswordCredential.class) {
            return null;
        }
        final ProcessBuilder processBuilder = builderProcessor.apply(new ProcessBuilder());
        processBuilder.redirectOutput(ProcessBuilder.Redirect.PIPE); // we want to capture the output of the process
        processBuilder.redirectError(NULL_FILE);
        final Process process;
        try {
            process = AccessController.doPrivileged((PrivilegedExceptionAction<Process>) processBuilder::start);
        } catch (PrivilegedActionException e) {
            try {
                throw e.getCause();
            } catch (IOException | RuntimeException | Error e2) {
                throw e2;
            } catch (Throwable throwable) {
                throw new UndeclaredThrowableException(throwable);
            }
        }
        try {
            final String line;
            process.getOutputStream().close();
            try (InputStream output = process.getInputStream()) {
                try (BufferedReader outputReader = new BufferedReader(new InputStreamReader(output, outputCharset))) {
                    line = outputReader.readLine();
                }
            }
            final int exitCode;
            try {
                exitCode = process.waitFor();
            } catch (InterruptedException e) {
                process.destroyForcibly();
                while (process.isAlive()) try {
                    process.waitFor();
                } catch (InterruptedException ignored) {}
                Thread.currentThread().interrupt();
                throw log.credentialCommandInterrupted();
            }
            if (log.isTraceEnabled()) {
                log.tracef("Exit code from password command = %d", Integer.valueOf(exitCode));
            }

            if (line == null) {
                return null;
            }

            return credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, line.toCharArray())));
        } finally {
            // better clean up just in case
            process.destroyForcibly();
        }
    }

    /**
     * Construct a new builder instance.
     *
     * @return the new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for a command credential source.
     */
    public static final class Builder {
        Charset outputCharset = Charset.defaultCharset();
        SecurityFactory<PasswordFactory> passwordFactoryFactory = () -> PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Function<ProcessBuilder, ProcessBuilder> builderProcessor = Function.identity();

        Builder() {
        }

        /**
         * Add a command string to the list of command strings.
         *
         * @param commandString the literal string to add (must not be {@code null})
         * @return this builder
         */
        public Builder addCommand(String commandString) {
            checkNotNullParam("commandString", commandString);
            checkNotEmptyParam("commandString", commandString);
            builderProcessor = builderProcessor.andThen(pb -> {
                pb.command().add(commandString);
                return pb;
            });
            return this;
        }

        /**
         * Add a command string supplier result to the list of command strings.  If the supplier returns {@code null} or
         * an empty string, no string is added at that time.  The supplier is evaluated every time a command is run.
         *
         * @param commandStringSupplier the string supplier to get the string from (must not be {@code null})
         * @return this builder
         */
        public Builder addCommand(Supplier<String> commandStringSupplier) {
            checkNotNullParam("commandString", commandStringSupplier);
            builderProcessor = builderProcessor.andThen(pb -> {
                final String string = commandStringSupplier.get();
                if (string != null && ! string.isEmpty()) pb.command().add(string);
                return pb;
            });
            return this;
        }

        /**
         * Add a command string provider to the list of command strings.  The provider can add multiple strings to
         * the consumer that is provided to it.  The provider must not provide {@code null} or empty strings.
         *
         * @param consumer the consumer which can provide the command strings to add (must not be {@code null})
         * @return this builder
         */
        public Builder addCommand(Consumer<Consumer<String>> consumer) {
            checkNotNullParam("commandString", consumer);
            builderProcessor = builderProcessor.andThen(pb -> {
                consumer.accept(string -> pb.command().add(checkNotEmptyParam("string", checkNotNullParam("string", string))));
                return pb;
            });
            return this;
        }

        /**
         * Add an environment value to the process environment.
         *
         * @param key the environment variable name (must not be {@code null})
         * @param value the environment variable value (must not be {@code null})
         * @return this builder
         */
        public Builder addEnvironment(String key, String value) {
            checkNotNullParam("key", key);
            checkNotEmptyParam("key", key);
            checkNotNullParam("value", value);
            checkNotEmptyParam("value", value);
            builderProcessor = builderProcessor.andThen(pb -> {
                pb.environment().put(key, value);
                return pb;
            });
            return this;
        }

        /**
         * Add multiple environment values to the process environment.  The consumer is called once for every command
         * execution.
         *
         * @param consumer a consumer which can provide key-value pairs to add to the environment (must not be {@code null})
         * @return this builder
         */
        public Builder addEnvironment(Consumer<BiConsumer<String, String>> consumer) {
            checkNotNullParam("consumer", consumer);
            builderProcessor = builderProcessor.andThen(pb -> {
                consumer.accept((key, value) -> pb.environment().put(checkNotEmptyParam("key", checkNotNullParam("key", key)), checkNotEmptyParam("value", checkNotNullParam("value", value))));
                return pb;
            });
            return this;
        }

        /**
         * Remove an environment variable from the process environment.
         *
         * @param key the environment variable name (must not be {@code null})
         * @return this builder
         */
        public Builder removeEnvironment(String key) {
            checkNotNullParam("key", key);
            checkNotEmptyParam("key", key);
            builderProcessor = builderProcessor.andThen(pb -> {
                pb.environment().remove(key);
                return pb;
            });
            return this;
        }

        /**
         * Set the working directory of the target process.
         *
         * @param directory the directory (must not be {@code null})
         * @return this builder
         */
        public Builder setWorkingDirectory(File directory) {
            checkNotNullParam("directory", directory);
            builderProcessor = builderProcessor.andThen(pb -> pb.directory(directory));
            return this;
        }

        /**
         * Set the provider to use to find the password factory.  If this method is not called, the default is used.
         *
         * @param provider the provider to use (must not be {@code null})
         * @return this builder
         */
        public Builder setPasswordFactoryProvider(Provider provider) {
            checkNotNullParam("provider", provider);
            passwordFactoryFactory = () -> PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, provider);
            return this;
        }

        /**
         * Set the output character set (encoding) to expect from the process.  If this method is not called, the
         * system default character set is used.
         *
         * @param charset the character set to use (must not be {@code null})
         * @return this builder
         */
        public Builder setOutputCharset(Charset charset) {
            checkNotNullParam("charset", charset);
            this.outputCharset = charset;
            return this;
        }

        /**
         * Construct the credential source instance.
         *
         * @return the credential source
         * @throws GeneralSecurityException if there was a failure constructing the password factory
         */
        public CommandCredentialSource build() throws GeneralSecurityException {
            return new CommandCredentialSource(this);
        }
    }
}
