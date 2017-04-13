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
import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.function.Supplier;

/**
 * An audit endpoint to record all audit events to a local file.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class FileAuditEndpoint implements AuditEndpoint {

    private static final byte[] LINE_TERMINATOR = System.lineSeparator().getBytes(StandardCharsets.UTF_8);

    private volatile boolean accepting = true;

    private final Supplier<DateFormat> dateFormatSupplier;
    private final boolean syncOnAccept;

    private File file;
    private FileDescriptor fileDescriptor;
    private OutputStream outputStream;

    FileAuditEndpoint(Builder builder) throws IOException {
        this.dateFormatSupplier = builder.dateFormatSupplier;
        this.syncOnAccept = builder.syncOnAccept;
        setFile(builder.location.toFile());
    }

    protected void setFile(final File file) throws IOException {
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

    protected File getFile() {
        return file;
    }

    private void safeClose(Closeable c) {
        try {
            if (c != null) c.close();
        } catch (Exception e) {
            audit.trace(e);
        }
    }

    protected void write(byte[] bytes) throws IOException {
        outputStream.write(bytes);
    }

    protected void preWrite(Date date) {
        // NO-OP by default
    }

    @Override
    public void accept(EventPriority t, String u) throws IOException {
        if (!accepting) return;
        Date date = new Date();

        synchronized(this) {
            if (!accepting) return; // We may have been waiting to get in here.

            preWrite(date);

            boolean started = false;

            try {
                write(dateFormatSupplier.get().format(date).getBytes(StandardCharsets.UTF_8));
                started = true;
                write(new byte[]{','});
                write(t.toString().getBytes(StandardCharsets.UTF_8));
                write(new byte[]{','});
                write(u.getBytes(StandardCharsets.UTF_8));
                write(LINE_TERMINATOR);
            } catch (IOException e) {
                throw started ? audit.partialSecurityEventWritten(e) : e;
            }

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
     * Close opened file streams.
     * Must be called synchronized block together with reopening using {@code setFile()}.
     */
    protected void closeStreams() throws IOException {
        outputStream.flush();
        fileDescriptor.sync();
        outputStream.close();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Supplier<DateFormat> dateFormatSupplier = SimpleDateFormat::new;
        private Path location = new File("audit.log").toPath();
        private boolean syncOnAccept = true;

        Builder() {
        }

        /**
         * Set the {@link Supplier<DateFormat>} to obtain the formatter for dates.
         *
         * @param dateFormatSupplier the {@link Supplier<DateFormat>} to obtain the formatter for dates.
         * @return this builder.
         */
        public Builder setDateFormatSupplier(Supplier<DateFormat> dateFormatSupplier) {
            this.dateFormatSupplier = checkNotNullParam("dateFormatSupplier", dateFormatSupplier);

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

        public AuditEndpoint build() throws IOException {
            return new FileAuditEndpoint(this);
        }

    }

}
