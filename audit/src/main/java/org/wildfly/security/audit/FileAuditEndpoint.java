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
import static org.wildfly.security.audit.ElytronMessages.audit;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
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

    private static final String LINE_TERMINATOR = System.lineSeparator();

    private volatile boolean accepting = true;

    private final Supplier<DateTimeFormatter> dateTimeFormatterSupplier;
    private final boolean syncOnAccept;
    private final boolean flushOnAccept;

    private File file;
    private FileDescriptor fileDescriptor;
    private Writer writer;
    private Charset charset;
    /**  Clock providing access to current time. */
    protected final Clock clock;

    FileAuditEndpoint(Builder builder) throws IOException {
        this.dateTimeFormatterSupplier = builder.dateTimeFormatterSupplier;
        this.syncOnAccept = builder.syncOnAccept;
        this.flushOnAccept = builder.flushOnAccept;
        this.clock = builder.clock;
        this.charset = builder.charset != null ? builder.charset : StandardCharsets.UTF_8;
        setFile(builder.location.toFile());
    }

    void setFile(final File file) throws IOException {
        boolean isFileSet = false;
        final FileOutputStream fos = new FileOutputStream(file, true);
        try {
            final Writer writer = new OutputStreamWriter(new BufferedOutputStream(fos), this.charset);
            try {
                this.fileDescriptor = fos.getFD();
                this.writer = writer;
                this.file = file;
                isFileSet = true;
            } finally {
                if (! isFileSet) {
                    safeClose(writer);
                }
            }
        } finally {
            if (! isFileSet) {
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
     * Method called to write given String to the target local file.
     * This method can be overridden by subclasses to modify data written into file (to encrypt them for example),
     * or just for counting amount of written bytes for needs of log rotation and similar.
     *
     * This method can be invoked only in synchronization block surrounding one log message processing.
     *
     * @param toWrite the String to be written into the target local file
     */
    void write(String toWrite) throws IOException {
        writer.write(toWrite);
    }

    /**
     * Method called before writing into local file.
     * This method is NO-OP by default. It is intended to be overridden by subclasses
     * which need to perform some operation before every writing into the target local file.
     *
     * This method can be invisFileSeted only in synchronization block surrounding one log message processing.
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

        StringBuffer buffer = new StringBuffer();
        buffer.append(dateTimeFormatterSupplier.get().format(instant));
        buffer.append(',');
        buffer.append(priority.toString());
        buffer.append(',');
        buffer.append(message);
        buffer.append(LINE_TERMINATOR);
        String toWrite = buffer.toString();

        synchronized(this) {
            if (!accepting) return; // We may have been waiting to get in here.

            preWrite(instant);
            write(toWrite);

            if (flushOnAccept) writer.flush();
            if (syncOnAccept) fileDescriptor.sync();
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
        writer.flush();
        fileDescriptor.sync();
        writer.close();
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
        private boolean flushOnAccept = true;
        private boolean flushSet = false;
        private Charset charset;

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
         * Sets if the output should be flushed on each event accepted.
         * If not set, flushing is done when output buffers synchronization is set.
         *
         * @param flushOnAccept should the output be flushed on each event accepted.
         * @return this builder.
         * @since 1.3.0
         */
        public Builder setFlushOnAccept(boolean flushOnAccept) {
            this.flushOnAccept = flushOnAccept;
            this.flushSet = true;

            return this;
        }

        /**
         * Sets if the system output buffers should be forced to be synchronized on each event accepted. Enabled by default.
         * Output flushing can be set independently using {@link #setFlushOnAccept(boolean)} but defaults to this value.
         *
         * @param syncOnAccept should the system output buffers be forced to be synchronized on each event accepted.
         * @return this builder.
         */
        public Builder setSyncOnAccept(boolean syncOnAccept) {
            this.syncOnAccept = syncOnAccept;
            if (! flushSet) this.flushOnAccept = syncOnAccept;

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
         * Set the file's character set.
         *
         * @param charset the character set
         * @return this builder.
         */
        public Builder setCharset(Charset charset) {
            this.charset = charset;

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
