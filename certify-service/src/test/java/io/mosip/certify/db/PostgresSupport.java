package io.mosip.certify.db;

import org.flywaydb.core.Flyway;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;

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
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Fresh databases, the Flyway chain with the service's defaults, today's DDL scripts and schema introspection on a Testcontainers PostgreSQL. */
final class PostgresSupport {

    static final String SCHEMA = "certify";
    static final Path DDL_DIR = locateDdlDir();
    static final int DDL_FILES = 15;

    private final PostgreSQLContainer<?> postgres;

    PostgresSupport(PostgreSQLContainer<?> postgres) {
        this.postgres = postgres;
    }

    /** Each test works on its own freshly created database so the tests are order-independent. */
    String freshDatabase(String name) throws SQLException {
        try (Connection c = dataSource(postgres.getDatabaseName()).getConnection(); Statement s = c.createStatement()) {
            s.execute("CREATE DATABASE " + name);
        }
        try (Connection c = dataSource(name).getConnection(); Statement s = c.createStatement()) {
            s.execute("CREATE SCHEMA " + SCHEMA);
        }
        return name;
    }

    DataSource dataSource(String database) {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl("jdbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432) + "/" + database + "?currentSchema=" + SCHEMA);
        ds.setUser(postgres.getUsername());
        ds.setPassword(postgres.getPassword());
        return ds;
    }

    Flyway flyway(String database) {
        return Flyway.configure()
                .dataSource(dataSource(database))
                .schemas(SCHEMA).defaultSchema(SCHEMA)
                .locations(FlywayDefaults.DEFAULT_LOCATIONS.toArray(new String[0]))
                .baselineOnMigrate(true)
                .baselineVersion(FlywayDefaults.BASELINE_VERSION)
                .validateOnMigrate(true)
                .load();
    }

    /** Runs the DDL files in the order ddl.sql lists them, skipping psql meta-commands, as a deployment does today. */
    void applyDdlScripts(String database) throws IOException, SQLException {
        List<String> order = new ArrayList<>();
        for (String line : Files.readAllLines(DDL_DIR.resolve("ddl.sql"))) {
            if (line.startsWith("\\ir ")) {
                order.add(line.substring(4).trim());
            }
        }
        assertEquals(DDL_FILES, order.size(), "ddl.sql lists every table file");
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

    Set<String> tables(String database) throws SQLException {
        return query(database, "SELECT table_name FROM information_schema.tables WHERE table_schema = '" + SCHEMA
                + "' AND table_name <> 'flyway_schema_history' ORDER BY 1");
    }

    Set<String> columns(String database) throws SQLException {
        return query(database, "SELECT table_name || '.' || column_name || ':' || data_type || ':' || udt_name || ':' || is_nullable"
                + " || ':' || COALESCE(column_default, '') || ':' || COALESCE(character_maximum_length::text, '')"
                + " FROM information_schema.columns WHERE table_schema = '" + SCHEMA + "' AND table_name <> 'flyway_schema_history'");
    }

    Set<String> indexes(String database) throws SQLException {
        return query(database, "SELECT indexdef FROM pg_indexes WHERE schemaname = '" + SCHEMA + "' AND tablename <> 'flyway_schema_history'");
    }

    Set<String> constraints(String database) throws SQLException {
        return query(database, "SELECT conrelid::regclass::text || ':' || conname || ':' || pg_get_constraintdef(oid) FROM pg_constraint"
                + " WHERE connamespace = '" + SCHEMA + "'::regnamespace AND conrelid::regclass::text NOT LIKE '%flyway_schema_history%'");
    }

    Set<String> query(String database, String sql) throws SQLException {
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
