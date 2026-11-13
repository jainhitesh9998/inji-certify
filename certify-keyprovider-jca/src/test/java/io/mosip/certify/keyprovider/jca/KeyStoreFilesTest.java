package io.mosip.certify.keyprovider.jca;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Keystore files (decision log 2026-11-13, F-10 review round 1): new ones {@code rw-------} whatever the umask; existing
 * ones keep owner, group and permissions; symbolic links are kept and the file they name is replaced; a directory the
 * service may not write falls back to writing the file in place.
 */
class KeyStoreFilesTest {

    static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");
    static final Set<PosixFilePermission> GROUP_READ = PosixFilePermissions.fromString("rw-r-----");

    @TempDir
    Path dir;

    @BeforeEach
    void posix() throws IOException {
        assumeTrue(Files.getFileStore(dir).supportsFileAttributeView(PosixFileAttributeView.class), "POSIX permissions");
    }

    @Test
    void aNewKeystoreIsOwnerOnlyUnderAPermissiveUmask() throws Exception {
        // the JVM cannot set its own umask: show the one in force would leave a plain file readable by group or others (022 does)
        Path plain = Files.write(dir.resolve("plain.bin"), new byte[] {1});
        Set<PosixFilePermission> umasked = Files.getPosixFilePermissions(plain);
        assumeTrue(umasked.contains(PosixFilePermission.GROUP_READ) || umasked.contains(PosixFilePermission.OTHERS_READ),
                "a umask such as 022 that leaves new files readable: " + umasked);

        Path keystore = dir.resolve("issuer.p12");
        KeyStoreFiles.write(keystore, out -> out.write(bytes("keys")));
        assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(keystore));
        assertArrayEquals(bytes("keys"), Files.readAllBytes(keystore));
        assertEquals(List.of("issuer.p12", "plain.bin"), listing(dir), "no temporary file left");
    }

    @Test
    void anExistingKeystoreKeepsItsOwnerGroupAndPermissions() throws Exception {
        Path keystore = Files.write(dir.resolve("issuer.p12"), bytes("old"));
        Files.setPosixFilePermissions(keystore, GROUP_READ);
        PosixFileAttributes before = Files.readAttributes(keystore, PosixFileAttributes.class);

        KeyStoreFiles.write(keystore, out -> out.write(bytes("new keys")));

        PosixFileAttributes after = Files.readAttributes(keystore, PosixFileAttributes.class);
        assertEquals(GROUP_READ, after.permissions(), "rw-r----- stays rw-r-----");
        assertEquals(before.owner(), after.owner());
        assertEquals(before.group(), after.group());
        assertArrayEquals(bytes("new keys"), Files.readAllBytes(keystore));
        assertNotEquals(before.fileKey(), after.fileKey(), "replaced by a move, not rewritten in place");
        assertEquals(List.of("issuer.p12"), listing(dir), "no temporary file left");

        Files.setPosixFilePermissions(keystore, PosixFilePermissions.fromString("rw-r--r--")); // as an older release left it
        KeyStoreFiles.write(keystore, out -> out.write(bytes("newer keys")));
        assertEquals(PosixFilePermissions.fromString("rw-r--r--"), Files.getPosixFilePermissions(keystore),
                "kept as the operator left it (a warning advises chmod o-r)");
    }

    @Test
    void aSymlinkedKeystoreStaysALinkAndItsTargetIsReplaced() throws Exception {
        Path secrets = Files.createDirectories(dir.resolve("secrets"));
        Path real = Files.write(secrets.resolve("keystore.p12"), bytes("old"));
        Files.setPosixFilePermissions(real, GROUP_READ);
        Path config = Files.createDirectories(dir.resolve("config"));
        Path link = Files.createSymbolicLink(config.resolve("issuer.p12"), Path.of("..", "secrets", "keystore.p12"));

        KeyStoreFiles.write(link, out -> out.write(bytes("new keys")));

        assertTrue(Files.isSymbolicLink(link), "the link is kept");
        assertEquals(Path.of("..", "secrets", "keystore.p12"), Files.readSymbolicLink(link));
        assertArrayEquals(bytes("new keys"), Files.readAllBytes(real), "the file it names is replaced");
        assertEquals(GROUP_READ, Files.getPosixFilePermissions(real));
        assertEquals(List.of("issuer.p12"), listing(config));
        assertEquals(List.of("keystore.p12"), listing(secrets), "no temporary file left beside the real file");

        Path dangling = Files.createSymbolicLink(config.resolve("next.p12"), Path.of("..", "secrets", "next.p12"));
        KeyStoreFiles.write(dangling, out -> out.write(bytes("first keys")));
        assertTrue(Files.isSymbolicLink(dangling), "a link to a file not yet written is kept too");
        assertArrayEquals(bytes("first keys"), Files.readAllBytes(secrets.resolve("next.p12")));
        assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(secrets.resolve("next.p12"), LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void aDirectoryTheServiceMayNotWriteFallsBackToWritingInPlace() throws Exception {
        Path locked = Files.createDirectories(dir.resolve("locked"));
        Path keystore = Files.write(locked.resolve("issuer.p12"), bytes("old"));
        Files.setPosixFilePermissions(keystore, GROUP_READ);
        Object inode = Files.readAttributes(keystore, BasicFileAttributes.class).fileKey();
        Files.setPosixFilePermissions(locked, PosixFilePermissions.fromString("r-xr-xr-x"));
        try {
            assumeFalse(Files.isWritable(locked), "not running as root");

            KeyStoreFiles.write(keystore, out -> out.write(bytes("new keys, longer than the old ones")));
            assertArrayEquals(bytes("new keys, longer than the old ones"), Files.readAllBytes(keystore));
            KeyStoreFiles.write(keystore, out -> out.write(bytes("short")));
            assertArrayEquals(bytes("short"), Files.readAllBytes(keystore), "truncated, then written");
            assertEquals(inode, Files.readAttributes(keystore, BasicFileAttributes.class).fileKey(), "the same file, written in place");
            assertEquals(GROUP_READ, Files.getPosixFilePermissions(keystore), "its permissions unchanged");
            assertEquals(List.of("issuer.p12"), listing(locked));

            assertThrows(AccessDeniedException.class, () -> KeyStoreFiles.write(locked.resolve("new.p12"), out -> out.write(bytes("x"))),
                    "a new keystore in a directory the service may not write cannot be created at all");
        } finally {
            Files.setPosixFilePermissions(locked, PosixFilePermissions.fromString("rwx------"));
        }
    }

    @Test
    void contentThatFailsLeavesThePreviousFileWhole() throws Exception {
        Path keystore = Files.write(dir.resolve("issuer.p12"), bytes("old"));
        assertThrows(GeneralSecurityException.class, () -> KeyStoreFiles.write(keystore, out -> {
            out.write(bytes("partial"));
            throw new GeneralSecurityException("cannot encrypt the key bag");
        }));
        assertArrayEquals(bytes("old"), Files.readAllBytes(keystore));
        assertEquals(List.of("issuer.p12"), listing(dir));
    }

    static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    static List<String> listing(Path directory) throws IOException {
        try (Stream<Path> files = Files.list(directory)) {
            return files.map(p -> p.getFileName().toString()).sorted().toList();
        }
    }
}
