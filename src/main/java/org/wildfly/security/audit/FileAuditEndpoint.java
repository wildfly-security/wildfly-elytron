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
package org.wildfly.security.audit;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.audit;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.function.Supplier;

/**
 * An audit endpoint to record all audit events to a local file.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class FileAuditEndpoint implements AuditEndpoint {

    private static final byte[] LINE_TERMINATOR = System.lineSeparator().getBytes(StandardCharsets.UTF_8);

    private volatile boolean accepting = true;

    private final Supplier<DateTimeFormatter> dateTimeFormatterSupplier;
    private final boolean syncOnAccept;

    private File file;
    private FileDescriptor fileDescriptor;
    private OutputStream outputStream;
    /**  Clock providing access to current time. */
    protected final Clock clock;

    FileAuditEndpoint(Builder builder) throws IOException {
        this.dateTimeFormatterSupplier = builder.dateTimeFormatterSupplier;
        this.syncOnAccept = builder.syncOnAccept;
        this.clock = builder.clock;
        setFile(builder.location.toFile());
    }

    void setFile(final File file) throws IOException {
        boolean ok = false;
        final FileOutputStream fos = new FileOutputStream(file, true);
        try {
            final OutputStream bos = new BufferedOutputStream(fos);
            try {
                this.fileDescriptor = fos.getFD();
                this.outputStream = bos;
                this.file = file;
                ok = true;
            } finally {
                if (! ok) {
                    safeClose(bos);
                }
            }
        } finally {
            if (! ok) {
                safeClose(fos);
            }
        }
    }

    File getFile() {
        return file;
    }

    private void safeClose(Closeable c) {
        try {
            if (c != null) c.close();
        } catch (Exception e) {
            audit.trace("Unable to close", e);
        }
    }

    /**
     * Method called to write given byte array to the target local file.
     * This method can be overridden by subclasses to modify data written into file (to encrypt them for example),
     * or just for counting amount of written bytes for needs of log rotation and similar.
     *
     * This method can be invoked only in synchronization block surrounding one log message processing.
     *
     * @param bytes the data to be written into the target local file
     */
    void write(byte[] bytes) throws IOException {
        outputStream.write(bytes);
    }

    /**
     * Method called before writing into local file.
     * This method is NO-OP by default. It is intended to be overridden by subclasses
     * which need to perform some operation before every writing into the target local file.
     *
     * This method can be invoked only in synchronization block surrounding one log message processing.
     *
     * @param instant time of the message acceptance
     */
    void preWrite(Instant instant) {
        // NO-OP by default
    }

    /**
     * Accept formatted security event message to be processed written into target local file.
     *
     * @param priority priority of the logged message
     * @param message the logged message
     * @throws IOException when writing into the target local file fails
     */
    @Override
    public void accept(EventPriority priority, String message) throws IOException {
        if (!accepting) return;
        Instant instant = clock.instant();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(dateTimeFormatterSupplier.get().format(instant).getBytes(StandardCharsets.UTF_8));
        baos.write(',');
        baos.write(priority.toString().getBytes(StandardCharsets.UTF_8));
        baos.write(',');
        baos.write(message.getBytes(StandardCharsets.UTF_8));
        baos.write(LINE_TERMINATOR);
        byte[] toWrite = baos.toByteArray();

        synchronized(this) {
            if (!accepting) return; // We may have been waiting to get in here.

            preWrite(instant);
            write(toWrite);

            if (syncOnAccept) {
                outputStream.flush();
                fileDescriptor.sync();
            }
        }
    }

    @Override
    public void close() throws IOException {
        accepting = false;

        synchronized (this) {
            closeStreams();
        }
    }

    /**
     * Close opened file streams. Can be called by subclasses for needs of target file changing.
     * Must be called in synchronized block together with reopening using {@code setFile()}.
     */
    void closeStreams() throws IOException {
        outputStream.flush();
        fileDescriptor.sync();
        outputStream.close();
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link FileAuditEndpoint}.
     *
     * @return a new {@link Builder} capable of building a {@link FileAuditEndpoint}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for file audit endpoints.
     */
    public static class Builder {

        private Clock clock = Clock.systemUTC();
        private Supplier<DateTimeFormatter> dateTimeFormatterSupplier = () -> DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT).withZone(ZoneId.systemDefault());
        private Path location = new File("audit.log").toPath();
        private boolean syncOnAccept = true;

        Builder() {
        }

        /**
         * Set the supplier to obtain the {@link DateTimeFormatter} for dates.
         * The supplied formatter has to have a time zone configured.
         *
         * @param dateTimeFormatterSupplier the supplier to obtain the {@link DateTimeFormatter}
         * @return this builder.
         */
        public Builder setDateTimeFormatterSupplier(Supplier<DateTimeFormatter> dateTimeFormatterSupplier) {
            this.dateTimeFormatterSupplier = checkNotNullParam("dateTimeFormatterSupplier", dateTimeFormatterSupplier);

            return this;
        }

        /**
         * Set the location to write the audit events to.
         *
         * @param location the location to write the audit events to.
         * @return this builder.
         */
        public Builder setLocation(Path location) {
            this.location = checkNotNullParam("location", location);

            return this;
        }

        /**
         * Sets if the output should be flushed and system buffers forces to synchronize on each event accepted.
         *
         * @param syncOnAccept should the output be flushed and system buffers forces to synchronize on each event accepted.
         * @return this builder.
         */
        public Builder setSyncOnAccept(boolean syncOnAccept) {
            this.syncOnAccept = syncOnAccept;

            return this;
        }

        /**
         * Sets the {@link Clock} instance the resulting {@link FileAuditEndpoint} should use to query the current time.
         * For testing purposes only, therefore package visible.
         *
         * @param clock the clock to query the current time
         * @return this builder
         */
        Builder setClock(Clock clock) {
            this.clock = clock;

            return this;
        }

        /**
         * Construct a new file audit endpoint.
         *
         * @return the built file audit endpoint.
         */
        public AuditEndpoint build() throws IOException {
            return new FileAuditEndpoint(this);
        }

    }

}
