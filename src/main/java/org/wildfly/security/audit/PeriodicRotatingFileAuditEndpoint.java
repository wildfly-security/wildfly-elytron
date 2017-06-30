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
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAdjusters;
import java.time.temporal.WeekFields;
import java.util.Locale;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.audit;

/**
 * An audit endpoint which rotates the log at a preset time interval.
 *
 * Based on {@link org.jboss.logmanager.handlers.PeriodicSizeRotatingFileHandler}.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 * @author <a href="mailto:jperkins@redhat.com">James R. Perkins</a>
 * @author <a href="mailto:yborgess@redhat.com">Yeray Borges</a>
 */
public class PeriodicRotatingFileAuditEndpoint extends FileAuditEndpoint {

    private final DateTimeFormatter format;
    private final Period period;
    private final ZoneId timeZone;
    private long nextRollover = Long.MAX_VALUE;
    private String nextSuffix;

    PeriodicRotatingFileAuditEndpoint(Builder builder) throws IOException {
        super(builder);
        this.format = builder.format;
        this.period = builder.period;
        this.timeZone = builder.timeZone;

        final File file = getFile();
        calcNextRollover(file != null && file.lastModified() > 0 ? file.lastModified() : System.currentTimeMillis());
    }

    @Override
    protected void preWrite(Instant instant) {
        final long recordMillis = instant.toEpochMilli();
        if (recordMillis >= nextRollover) {
            try {
                final File file = getFile();
                if (file == null) {
                    // no file is set; a direct output stream or writer was specified
                    return;
                }
                closeStreams(); // close the original file (some OSes won't let you move/rename a file that is open)
                final Path target = Paths.get(file.toPath() + nextSuffix);
                Files.move(file.toPath(), target, StandardCopyOption.REPLACE_EXISTING);
                setFile(file);
            } catch (IOException e) {
                audit.unableToRotateLogFile(e);
            }
            calcNextRollover(recordMillis);
        }
    }

    /**
     * For given time and period obtains time when should be new log file started
     */
    private void calcNextRollover(final long fromTime) {
        if (period == Period.NEVER || format == null) {
            nextRollover = Long.MAX_VALUE;
            return;
        }
        ZonedDateTime zonedDateTime = ZonedDateTime.ofInstant(Instant.ofEpochMilli(fromTime), timeZone);
        nextSuffix = format.format(zonedDateTime);
        switch (period) {
            case YEAR:
                zonedDateTime = zonedDateTime.truncatedTo(ChronoUnit.DAYS)
                        .withDayOfYear(1)
                        .plus(1, ChronoUnit.YEARS);
                break;
            case MONTH:
                zonedDateTime =  zonedDateTime.truncatedTo(ChronoUnit.DAYS)
                        .withDayOfMonth(1)
                        .plus(1,ChronoUnit.MONTHS);
                break;
            case WEEK:
                zonedDateTime = zonedDateTime.truncatedTo(ChronoUnit.DAYS)
                        .with(TemporalAdjusters.next(WeekFields.of(Locale.getDefault()).getFirstDayOfWeek()));
                break;
            case DAY:
                zonedDateTime = zonedDateTime.truncatedTo(ChronoUnit.DAYS)
                        .plus(1, ChronoUnit.DAYS);
                break;
            case HALF_DAY:
                ZonedDateTime halfDay = ZonedDateTime.from(zonedDateTime).truncatedTo(ChronoUnit.DAYS)
                        .plus(1, ChronoUnit.HALF_DAYS);
                if ( zonedDateTime.isBefore(halfDay) ) {
                    zonedDateTime = halfDay;
                }else{
                    zonedDateTime = halfDay.plus(1, ChronoUnit.HALF_DAYS);
                }
                break;
            case HOUR:
                zonedDateTime = zonedDateTime.truncatedTo(ChronoUnit.HOURS)
                        .plus(1, ChronoUnit.HOURS);
                break;
            case MINUTE:
                zonedDateTime = zonedDateTime.truncatedTo(ChronoUnit.MINUTES)
                        .plus(1, ChronoUnit.MINUTES);
        }
        nextRollover = zonedDateTime.toInstant().toEpochMilli();
    }

    /**
     * Possible period values. Keep in strictly ascending order of magnitude.
     */
    protected enum Period {
        MINUTE,
        HOUR,
        HALF_DAY,
        DAY,
        WEEK,
        MONTH,
        YEAR,
        NEVER,
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends FileAuditEndpoint.Builder {
        DateTimeFormatter format;
        Period period = Period.NEVER;
        ZoneId timeZone = ZoneId.systemDefault();

        Builder() {
            super();
        }

        /**
         * Set the configured time zone for this handler.
         *
         * @param timeZone the configured time zone
         * @return this builder.
         */
        public Builder setTimeZone(ZoneId timeZone) {
            this.timeZone = checkNotNullParam("timeZone", timeZone);

            return this;
        }

        /**
         * Set the suffix string.  The string is in a format which can be understood by {@link java.time.format.DateTimeFormatter}.
         * The period of the rotation is automatically calculated based on the suffix.
         *
         * @param suffix the suffix
         * @throws IllegalArgumentException if the suffix is not valid
         */
        public Builder setSuffix(String suffix) throws IllegalArgumentException {
            format = DateTimeFormatter.ofPattern(suffix).withZone(timeZone);
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

        /**
         * Construct a new instance.
         *
         * @return the built audit endpoint.
         * @throws IOException  if an I/O error occurs.
         */
        @Override
        public AuditEndpoint build() throws IOException {
            return new PeriodicRotatingFileAuditEndpoint(this);
        }
    }

    private static <T extends Comparable<? super T>> T min(T a, T b) {
        return a.compareTo(b) <= 0 ? a : b;
    }
}