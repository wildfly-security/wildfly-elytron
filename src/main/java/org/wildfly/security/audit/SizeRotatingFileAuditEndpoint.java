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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.audit;

/**
 * An audit endpoint which rotates the log when log file size reach given value.
 * <p>
 * Moves old log records into files tagged by index - the older has the higher index.
 * When index reach {@code maxBackupIndex}, the oldest log file is removed,
 * so there are at most {@code maxBackupIndex + 1} log files.
 * <p>
 * Based on {@link org.jboss.logmanager.handlers.PeriodicSizeRotatingFileHandler}.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 * @author <a href="mailto:yborgess@redhat.com">Yeray Borges</a>
 */
public class SizeRotatingFileAuditEndpoint extends FileAuditEndpoint {
    private final long rotateSize;
    private final int maxBackupIndex;
    private final boolean rotateOnBoot;
    private long currentSize = 0;
    private final String suffix;
    private final DateTimeFormatter dateTimeFormatter;

    SizeRotatingFileAuditEndpoint(Builder builder) throws IOException {
        super(builder);
        this.rotateSize = builder.rotateSize;
        this.maxBackupIndex = builder.maxBackupIndex;
        this.rotateOnBoot = builder.rotateOnBoot;
        this.suffix = builder.suffix;
        this.dateTimeFormatter = this.suffix != null ? DateTimeFormatter.ofPattern(this.suffix).withZone(builder.timeZone) : null;

        final File file = getFile();
        if (rotateOnBoot && maxBackupIndex > 0 && file != null && file.exists() && file.length() > 0L) {
            rotate(file);
        }
    }

    @Override
    protected void write(byte[] bytes) throws IOException {
        super.write(bytes);
        currentSize += bytes.length;
    }

    @Override
    protected void preWrite(Instant instant) {
        if (currentSize > rotateSize && maxBackupIndex > 0) {
            try {
                final File file = getFile();
                if (file == null) {
                    // no file is set; a direct output stream or writer was specified
                    return;
                }
                rotate(file);
                currentSize = 0;
            } catch (IOException e) {
                audit.unableToRotateLogFile(e);
            }
        }
    }

    /**
     * Moves file to file.1, file.1 to file.2 etc. Removes file.{maxBackupIndex}
     */
    private void rotate(final File file) throws IOException {
        closeStreams();
        final String suffix = dateTimeFormatter != null ? dateTimeFormatter.format(ZonedDateTime.now(clock)) : "";
        final Path fileWithSuffix = Paths.get(file.getAbsolutePath() + suffix);
        Files.deleteIfExists(Paths.get(fileWithSuffix + "." + maxBackupIndex));
        for (int i = maxBackupIndex - 1; i >= 1; i--) {
            final Path src = Paths.get(fileWithSuffix + "." + i);
            if (Files.exists(src)) {
                final Path target = Paths.get(fileWithSuffix + "." + (i + 1));
                Files.move(src, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        Files.move(file.toPath(), Paths.get(fileWithSuffix + ".1"), StandardCopyOption.REPLACE_EXISTING);
        setFile(file);
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link SizeRotatingFileAuditEndpoint}.
     *
     * @return a new {@link Builder} capable of building a {@link SizeRotatingFileAuditEndpoint}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for size rotating file audit endpoints.
     */
    public static class Builder extends FileAuditEndpoint.Builder {

        private long rotateSize = 0xa0000L; // 10 MB by default
        private int maxBackupIndex = 1;
        private boolean rotateOnBoot;
        private String suffix;

        ZoneId timeZone = ZoneId.systemDefault();

        Builder() {
            super();
        }

        /**
         * Set the log file size the file should rotate at.
         *
         * @param rotateSize the size the file should rotate at
         * @return this builder.
         */
        public Builder setRotateSize(long rotateSize) {
            this.rotateSize = rotateSize;

            return this;
        }

        /**
         * Sets the suffix to be appended to the file name during the file rotation. The suffix does not play a role in
         * determining when the file should be rotated.
         * <p/>
         * The suffix must be a string understood by the  {@link java.time.format.DateTimeFormatter}.
         * <p/>
         * <b>Note:</b> Files will be rotated for the same suffix until reach the maximum backup index configured by {@link #setMaxBackupIndex(int)}.
         * If the suffix is resolved to a new value, any files rotated with a different suffix will not be deleted.
         * For example if the suffix is .yyyy-DD-mm, the maximum size was reached 20 times on the same day and the maxBackupIndex
         * was set to 10, then there will only be 10 files kept. What will not be purged is files from a previous day.
         *
         * @param suffix the suffix to place after the filename when the file is rotated
         */
        public Builder setSuffix(String suffix){
            this.suffix = suffix;

            return this;
        }

        /**
         * Set the maximum number of files to backup.
         *
         * @param maxBackupIndex the maximum number of files to backup
         * @return this builder.
         */
        public Builder setMaxBackupIndex(int maxBackupIndex) {
            this.maxBackupIndex = maxBackupIndex;

            return this;
        }

        /**
         * Set to a value of {@code true} if the file should be rotated before the a new file is set. The rotation only
         * happens if the file names are the same and the file has a {@link java.io.File#length() length} greater than 0.
         *
         * @param rotateOnBoot {@code true} to rotate on boot, otherwise {@code false}
         * @return this builder.
         */
        public SizeRotatingFileAuditEndpoint.Builder setRotateOnBoot(boolean rotateOnBoot) {
            this.rotateOnBoot = rotateOnBoot;

            return this;
        }

        /**
         * Set the configured time zone for this handler.
         *
         * @param timeZone the configured time zone
         * @return this builder.
         */
        public SizeRotatingFileAuditEndpoint.Builder setTimeZone(ZoneId timeZone) {
            this.timeZone = checkNotNullParam("timeZone", timeZone);

            return this;
        }

        /**
         * Construct a new instance.
         *
         * @return the built audit endpoint.
         * @throws IOException  if an I/O error occurs.
         */

        @Override
        public AuditEndpoint build() throws IOException {
            return new SizeRotatingFileAuditEndpoint(this);
        }
    }
}
