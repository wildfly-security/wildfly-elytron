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
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.audit;

/**
 * An audit endpoint which rotates the log at a preset time interval or the size of the log.
 *
 * Based on {@link org.jboss.logmanager.handlers.PeriodicSizeRotatingFileHandler}.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 */
public class RotatingFileAuditEndpoint extends FileAuditEndpoint {

    private final long rotateSize;
    private final int maxBackupIndex;
    private final boolean rotateOnBoot;
    private final SimpleDateFormat format;
    private final Period period;
    private final TimeZone timeZone;

    private String nextSuffix;
    private long nextRollover = Long.MAX_VALUE;
    private long currentSize = 0;

    RotatingFileAuditEndpoint(Builder builder) throws IOException {
        super(builder);
        this.rotateSize = builder.rotateSize;
        this.maxBackupIndex = builder.maxBackupIndex;
        this.rotateOnBoot = builder.rotateOnBoot;
        this.format = builder.format;
        this.period = builder.period;
        this.timeZone = builder.timeZone;

        final File file = getFile();
        calcNextRollover(file != null && file.lastModified() > 0 ? file.lastModified() : System.currentTimeMillis());
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
    protected void preWrite(Date date) {
        final long recordMillis = date.getTime();
        if (recordMillis >= nextRollover) { // time based rollover
            try {
                final File file = getFile();
                closeStreams(); // close the original file (some OSes won't let you move/rename a file that is open)
                final Path target = Paths.get(file.getAbsolutePath() + nextSuffix);
                Files.move(file.toPath(), target, StandardCopyOption.REPLACE_EXISTING);
                setFile(file);
                currentSize = 0;
            } catch (IOException e) {
                audit.unableToRotateLogFile(e);
            }
            calcNextRollover(recordMillis);
        } else if (currentSize > rotateSize && maxBackupIndex > 0) { // file size based rollover
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
        final Path fileWithSuffix = Paths.get(file.getAbsolutePath() + nextSuffix);
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
     * For given time and period obtains time when should be new log file started
     */
    private void calcNextRollover(final long fromTime) {
        if (period == Period.NEVER || format == null) {
            nextRollover = Long.MAX_VALUE;
            return;
        }
        nextSuffix = format.format(new Date(fromTime));
        final Calendar calendar = Calendar.getInstance(timeZone);
        calendar.setTimeInMillis(fromTime);
        final Period period = this.period;
        // clear out less-significant fields
        switch (period) {
            default:
            case YEAR:
                calendar.set(Calendar.MONTH, 0);
            case MONTH:
                calendar.set(Calendar.DAY_OF_MONTH, 0);
                calendar.clear(Calendar.WEEK_OF_MONTH);
            case WEEK:
                if (period == Period.WEEK) {
                    calendar.set(Calendar.DAY_OF_WEEK, calendar.getFirstDayOfWeek());
                } else {
                    calendar.clear(Calendar.DAY_OF_WEEK);
                }
                calendar.clear(Calendar.DAY_OF_WEEK_IN_MONTH);
            case DAY:
                calendar.set(Calendar.HOUR_OF_DAY, 0);
            case HALF_DAY:
                if (period == Period.HALF_DAY) {
                    calendar.set(Calendar.HOUR, 0);
                } else {
                    //We want both HOUR_OF_DAY and (HOUR + AM_PM) to be zeroed out
                    //This should ensure the hour is truly zeroed out
                    calendar.set(Calendar.HOUR, 0);
                    calendar.set(Calendar.AM_PM, 0);
                }
            case HOUR:
                calendar.set(Calendar.MINUTE, 0);
            case MINUTE:
                calendar.set(Calendar.SECOND, 0);
                calendar.set(Calendar.MILLISECOND, 0);
        }
        // increment the relevant field
        switch (period) {
            case YEAR:
                calendar.add(Calendar.YEAR, 1);
                break;
            case MONTH:
                calendar.add(Calendar.MONTH, 1);
                break;
            case WEEK:
                calendar.add(Calendar.WEEK_OF_YEAR, 1);
                break;
            case DAY:
                calendar.add(Calendar.DAY_OF_MONTH, 1);
                break;
            case HALF_DAY:
                calendar.add(Calendar.AM_PM, 1);
                break;
            case HOUR:
                calendar.add(Calendar.HOUR_OF_DAY, 1);
                break;
            case MINUTE:
                calendar.add(Calendar.MINUTE, 1);
                break;
        }
        nextRollover = calendar.getTimeInMillis();
    }

    /**
     * Possible period values.  Keep in strictly ascending order of magnitude.
     */
    public enum Period {
        MINUTE,
        HOUR,
        HALF_DAY,
        DAY,
        WEEK,
        MONTH,
        YEAR,
        NEVER,
    }

    private static <T extends Comparable<? super T>> T min(T a, T b) {
        return a.compareTo(b) <= 0 ? a : b;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends FileAuditEndpoint.Builder {

        private long rotateSize = 0xa0000L; // 10 MB by default
        private int maxBackupIndex = 1;
        private boolean rotateOnBoot;

        SimpleDateFormat format;
        Period period = Period.NEVER;
        TimeZone timeZone = TimeZone.getDefault();

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
        public Builder setRotateOnBoot(boolean rotateOnBoot) {
            this.rotateOnBoot = rotateOnBoot;

            return this;
        }

        /**
         * Set the configured time zone for this handler.
         *
         * @param timeZone the configured time zone
         * @return this builder.
         */
        public Builder setTimeZone(TimeZone timeZone) {
            this.timeZone = checkNotNullParam("timeZone", timeZone);

            return this;
        }

        /**
         * Set the suffix string.  The string is in a format which can be understood by {@link java.text.SimpleDateFormat}.
         * The period of the rotation is automatically calculated based on the suffix.
         *
         * @param suffix the suffix
         * @throws IllegalArgumentException if the suffix is not valid
         */
        public Builder setSuffix(String suffix) throws IllegalArgumentException {
            format = new SimpleDateFormat(suffix);
            format.setTimeZone(timeZone);
            final int len = suffix.length();
            period = Period.NEVER;
            for (int i = 0; i < len; i ++) {
                switch (suffix.charAt(i)) {
                    case 'y': period = min(period, Period.YEAR); break;
                    case 'M': period = min(period, Period.MONTH); break;
                    case 'w':
                    case 'W': period = min(period, Period.WEEK); break;
                    case 'D':
                    case 'd':
                    case 'F':
                    case 'E': period = min(period, Period.DAY); break;
                    case 'a': period = min(period, Period.HALF_DAY); break;
                    case 'H':
                    case 'k':
                    case 'K':
                    case 'h': period = min(period, Period.HOUR); break;
                    case 'm': period = min(period, Period.MINUTE); break;
                    case '\'': while (suffix.charAt(++i) != '\''){} break;
                    case 's':
                    case 'S': throw audit.rotatingBySecondUnsupported(suffix);
                }
            }

            return this;
        }

        @Override
        public AuditEndpoint build() throws IOException {
            return new RotatingFileAuditEndpoint(this);
        }

    }
}
