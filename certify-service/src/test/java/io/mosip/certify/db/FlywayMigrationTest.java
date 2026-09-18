package io.mosip.certify.db;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.io.IOException;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Flyway chain is exercised against a real PostgreSQL (docs/design/08-database.md):
 * an empty database gets the full schema, a database created from db_scripts (what every deployment has today)
 * is baselined and then only the later migrations run, and both roads end in the same schema.
 */
@Testcontainers(disabledWithoutDocker = true)
class FlywayMigrationTest {

    static final String SCHEMA = PostgresSupport.SCHEMA;
    static final Path DDL_DIR = PostgresSupport.DDL_DIR;

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");
    static final PostgresSupport SUPPORT = new PostgresSupport(POSTGRES);

    @Test
    void emptyDatabaseGetsTheFullSchemaFromTheBaselines() throws SQLException {
        String db = freshDatabase("flyway_empty");
        MigrateResult result = flyway(db).migrate();
        assertEquals(5, result.migrationsExecuted, "core, keymanager, verify and as baselines, then 1.1.0");
        assertEquals(17, tables(db).size(), tables(db).toString());
        List<String> versions = Arrays.stream(flyway(db).info().applied()).map(MigrationInfo::getVersion)
                .map(Object::toString).toList();
        assertEquals(List.of("1.0.0.000", "1.0.0.001", "1.0.0.002", "1.0.0.003", "1.1.0.000"), versions);
    }

    @Test
    void databaseCreatedFromDbScriptsIsBaselinedThenUpgraded() throws Exception {
        String db = freshDatabase("ddl_baseline");
        applyDdlScripts(db);
        assertEquals(15, tables(db).size(), tables(db).toString());

        MigrateResult result = flyway(db).migrate();
        assertEquals(1, result.migrationsExecuted, "an existing schema is adopted (baseline), then only the 1.1.0 migration runs");
        MigrationInfo[] applied = flyway(db).info().applied();
        assertEquals(2, applied.length);
        assertEquals(FlywayDefaults.BASELINE_VERSION, applied[0].getVersion().toString());
        assertTrue(applied[0].getType().isBaseline(), "the first history row is the baseline");
        assertEquals("1.1.0.000", applied[1].getVersion().toString());
        assertEquals(17, tables(db).size());
        // a second run is a no-op
        assertEquals(0, flyway(db).migrate().migrationsExecuted);
    }

    @Test
    void flywayBaselinesAndDbScriptsProduceTheSameSchema() throws Exception {
        String viaFlyway = freshDatabase("cmp_flyway");
        String viaDdl = freshDatabase("cmp_ddl");
        flyway(viaFlyway).migrate();
        applyDdlScripts(viaDdl);
        flyway(viaDdl).migrate();
        assertEquals(columns(viaDdl), columns(viaFlyway), "columns differ between db_scripts and the Flyway baselines");
        assertEquals(indexes(viaDdl), indexes(viaFlyway), "indexes differ between db_scripts and the Flyway baselines");
        assertEquals(constraints(viaDdl), constraints(viaFlyway), "constraints differ between db_scripts and the Flyway baselines");
    }

    static String freshDatabase(String name) throws SQLException { return SUPPORT.freshDatabase(name); }
    static DataSource dataSource(String database) { return SUPPORT.dataSource(database); }
    static Flyway flyway(String database) { return SUPPORT.flyway(database); }
    static void applyDdlScripts(String database) throws IOException, SQLException { SUPPORT.applyDdlScripts(database); }
    static Set<String> tables(String database) throws SQLException { return SUPPORT.tables(database); }
    static Set<String> columns(String database) throws SQLException { return SUPPORT.columns(database); }
    static Set<String> indexes(String database) throws SQLException { return SUPPORT.indexes(database); }
    static Set<String> constraints(String database) throws SQLException { return SUPPORT.constraints(database); }
}
