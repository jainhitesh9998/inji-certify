package io.mosip.certify.db;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.output.MigrateResult;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Flyway chain is exercised against a real PostgreSQL (docs/design/08-database.md):
 * an empty database gets the full schema, a database created from db_scripts (what every deployment has today)
 * is baselined without running anything, and both roads end in the same schema.
 */
@Testcontainers(disabledWithoutDocker = true)
class FlywayMigrationTest {

    static final String SCHEMA = "certify";
    static final Path DDL_DIR = locateDdlDir();

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");

    /** Each test works on its own freshly created database so the tests are order-independent. */
    static String freshDatabase(String name) throws SQLException {
        try (Connection c = dataSource(POSTGRES.getDatabaseName()).getConnection(); Statement s = c.createStatement()) {
            s.execute("CREATE DATABASE " + name);
        }
        try (Connection c = dataSource(name).getConnection(); Statement s = c.createStatement()) {
            s.execute("CREATE SCHEMA " + SCHEMA);
        }
        return name;
    }

    static DataSource dataSource(String database) {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl("jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/" + database
                + "?currentSchema=" + SCHEMA);
        ds.setUser(POSTGRES.getUsername());
        ds.setPassword(POSTGRES.getPassword());
        return ds;
    }

    static Flyway flyway(String database) {
        return Flyway.configure()
                .dataSource(dataSource(database))
                .schemas(SCHEMA).defaultSchema(SCHEMA)
                .locations(FlywayDefaults.DEFAULT_LOCATIONS.toArray(new String[0]))
                .baselineOnMigrate(true)
                .baselineVersion(FlywayDefaults.BASELINE_VERSION)
                .validateOnMigrate(true)
                .load();
    }

    @Test
    void emptyDatabaseGetsTheFullSchemaFromTheBaselines() throws SQLException {
        String db = freshDatabase("flyway_empty");
        MigrateResult result = flyway(db).migrate();
        assertEquals(4, result.migrationsExecuted, "core, keymanager, verify and as baselines");
        assertEquals(15, tables(db).size(), tables(db).toString());
        List<String> versions = Arrays.stream(flyway(db).info().applied()).map(MigrationInfo::getVersion)
                .map(Object::toString).toList();
        assertEquals(List.of("1.0.0.000", "1.0.0.001", "1.0.0.002", "1.0.0.003"), versions);
    }

    @Test
    void databaseCreatedFromDbScriptsIsBaselinedAndNotMigrated() throws Exception {
        String db = freshDatabase("ddl_baseline");
        applyDdlScripts(db);
        assertEquals(15, tables(db).size(), tables(db).toString());

        MigrateResult result = flyway(db).migrate();
        assertEquals(0, result.migrationsExecuted, "an existing schema is adopted, never re-created");
        MigrationInfo[] applied = flyway(db).info().applied();
        assertEquals(1, applied.length);
        assertEquals(FlywayDefaults.BASELINE_VERSION, applied[0].getVersion().toString());
        assertTrue(applied[0].getType().isBaseline(), "the single history row is the baseline");
        assertEquals(15, tables(db).size());
        // a second run is a no-op
        assertEquals(0, flyway(db).migrate().migrationsExecuted);
    }

    @Test
    void flywayBaselinesAndDbScriptsProduceTheSameSchema() throws Exception {
        String viaFlyway = freshDatabase("cmp_flyway");
        String viaDdl = freshDatabase("cmp_ddl");
        flyway(viaFlyway).migrate();
        applyDdlScripts(viaDdl);
        assertEquals(columns(viaDdl), columns(viaFlyway), "columns differ between db_scripts and the Flyway baselines");
        assertEquals(indexes(viaDdl), indexes(viaFlyway), "indexes differ between db_scripts and the Flyway baselines");
        assertEquals(constraints(viaDdl), constraints(viaFlyway), "constraints differ between db_scripts and the Flyway baselines");
    }

    /** Runs the DDL files in the order ddl.sql lists them, skipping psql meta-commands, as a deployment does today. */
    static void applyDdlScripts(String database) throws IOException, SQLException {
        List<String> order = new ArrayList<>();
        for (String line : Files.readAllLines(DDL_DIR.resolve("ddl.sql"))) {
            if (line.startsWith("\\ir ")) {
                order.add(line.substring(4).trim());
            }
        }
        assertEquals(15, order.size(), "ddl.sql lists every table file");
        try (Connection c = dataSource(database).getConnection(); Statement s = c.createStatement()) {
            s.execute("SET search_path TO " + SCHEMA);
            for (String file : order) {
                StringBuilder sql = new StringBuilder();
                for (String line : Files.readAllLines(DDL_DIR.resolve(file), StandardCharsets.UTF_8)) {
                    if (!line.startsWith("\\")) {
                        sql.append(line).append('\n');
                    }
                }
                s.execute(sql.toString());
            }
        }
    }

    static Set<String> tables(String database) throws SQLException {
        return query(database, "SELECT table_name FROM information_schema.tables WHERE table_schema = '" + SCHEMA
                + "' AND table_name <> 'flyway_schema_history' ORDER BY 1");
    }

    static Set<String> columns(String database) throws SQLException {
        return query(database, "SELECT table_name || '.' || column_name || ':' || data_type || ':' || udt_name || ':' || is_nullable"
                + " || ':' || COALESCE(column_default, '') || ':' || COALESCE(character_maximum_length::text, '')"
                + " FROM information_schema.columns WHERE table_schema = '" + SCHEMA + "' AND table_name <> 'flyway_schema_history'");
    }

    static Set<String> indexes(String database) throws SQLException {
        return query(database, "SELECT indexdef FROM pg_indexes WHERE schemaname = '" + SCHEMA + "' AND tablename <> 'flyway_schema_history'");
    }

    static Set<String> constraints(String database) throws SQLException {
        return query(database, "SELECT conrelid::regclass::text || ':' || conname || ':' || pg_get_constraintdef(oid) FROM pg_constraint"
                + " WHERE connamespace = '" + SCHEMA + "'::regnamespace AND conrelid::regclass::text NOT LIKE '%flyway_schema_history%'");
    }

    static Set<String> query(String database, String sql) throws SQLException {
        Set<String> out = new TreeSet<>();
        try (Connection c = dataSource(database).getConnection(); Statement s = c.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        }
        return out;
    }

    static Path locateDdlDir() {
        Path dir = Paths.get("").toAbsolutePath();
        while (dir != null) {
            Path candidate = dir.resolve("db_scripts").resolve("inji_certify");
            if (Files.isDirectory(candidate)) {
                return candidate;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("db_scripts/inji_certify not found above " + Paths.get("").toAbsolutePath());
    }
}
