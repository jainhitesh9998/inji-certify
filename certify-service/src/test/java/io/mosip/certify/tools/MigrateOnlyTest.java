package io.mosip.certify.tools;

import io.mosip.certify.datasource.file.FileDataSourceAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The migration job must not read or validate the demo file data sources (M-10 review). */
class MigrateOnlyTest {

    @Test
    void theMigrationJobExcludesTheFileDataSource() {
        assertTrue(MigrateOnly.AUTOCONFIGURATION_EXCLUDES.contains(FileDataSourceAutoConfiguration.class.getName()),
                "a broken demo file must not block a migration");
    }

    @Test
    void theExclusionIsAPropertyNotAnAnnotationOnTheScannedConfigurationClass() {
        // MigrateOnly is a @SpringBootConfiguration under io.mosip.certify: an @EnableAutoConfiguration(exclude) here
        // would remove the file data source from every context that scans it, the service included.
        EnableAutoConfiguration enable = MigrateOnly.class.getAnnotation(EnableAutoConfiguration.class);
        assertNotNull(enable);
        assertFalse(List.of(enable.exclude()).contains(FileDataSourceAutoConfiguration.class));
    }
}
