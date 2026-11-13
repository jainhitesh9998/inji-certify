package io.mosip.certify.keyprovider.jca;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystemLoopException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Keystore files (decision log 2026-11-13, F-10 review rounds 1 and 2): new ones {@code rw-------} whatever the umask and
 * moved into place atomically; existing ones rewritten in place, keeping owner, group, permissions and the native ACLs Java
 * cannot see, after an owner-only {@code <file>.bak} of the previous content; symbolic link chains kept, also through
 * symlinked directories, loops refused; a directory the service may not write still lets an existing file be rewritten; a
 * file the service may not write is left alone.
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
        assertEquals(List.of("issuer.p12", "plain.bin"), listing(dir), "no temporary file and, for a new keystore, no backup");
    }

    @Test
    void anExistingKeystoreIsRewrittenInPlaceAfterAnOwnerOnlyBackup() throws Exception {
        Path keystore = Files.write(dir.resolve("issuer.p12"), bytes("old keys, longer than the new ones"));
        Files.setPosixFilePermissions(keystore, GROUP_READ);
        PosixFileAttributes before = Files.readAttributes(keystore, PosixFileAttributes.class);

        KeyStoreFiles.write(keystore, out -> out.write(bytes("new keys")));

        PosixFileAttributes after = Files.readAttributes(keystore, PosixFileAttributes.class);
        assertArrayEquals(bytes("new keys"), Files.readAllBytes(keystore), "truncated, then written");
        assertEquals(before.fileKey(), after.fileKey(), "the same file, rewritten in place");
        assertEquals(GROUP_READ, after.permissions(), "rw-r----- stays rw-r-----");
        assertEquals(before.owner(), after.owner());
        assertEquals(before.group(), after.group());
        Path backup = dir.resolve("issuer.p12.bak");
        assertEquals(backup, KeyStoreFiles.backupOf(keystore));
        assertArrayEquals(bytes("old keys, longer than the new ones"), Files.readAllBytes(backup), "the previous keystore");
        assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(backup), "the backup is owner-only whatever the keystore's mode");
        assertEquals(List.of("issuer.p12", "issuer.p12.bak"), listing(dir), "no temporary file left");

        Files.setPosixFilePermissions(keystore, PosixFilePermissions.fromString("rw-r--r--")); // as an older release left it
        Object backupKey = Files.readAttributes(backup, BasicFileAttributes.class).fileKey();
        KeyStoreFiles.write(keystore, out -> out.write(bytes("newer keys")));
        assertEquals(PosixFilePermissions.fromString("rw-r--r--"), Files.getPosixFilePermissions(keystore),
                "kept as the operator left it (a warning advises chmod o-r)");
        assertArrayEquals(bytes("new keys"), Files.readAllBytes(backup), "the backup follows each write");
        assertFalse(backupKey.equals(Files.readAttributes(backup, BasicFileAttributes.class).fileKey()), "replaced by a move");
        assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(backup));
    }

    /** The keystore's group, when the operator gave it one other than the service user's primary group, is kept. */
    @Test
    void anOperatorsGroupIsKept() throws Exception {
        Path keystore = Files.write(dir.resolve("issuer.p12"), bytes("old"));
        PosixFileAttributeView view = Files.getFileAttributeView(keystore, PosixFileAttributeView.class);
        GroupPrincipal primary = view.readAttributes().group();
        Optional<GroupPrincipal> other = Optional.empty();
        for (String name : run("id", "-Gn").orElse("").trim().split("\\s+")) {
            if (name.isBlank() || name.equals(primary.getName())) {
                continue;
            }
            try {
                GroupPrincipal group = dir.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName(name);
                view.setGroup(group);
                other = Optional.of(group);
                break;
            } catch (IOException e) {
                // not a group this user may give the file; try the next one
            }
        }
        assumeTrue(other.isPresent(), "the test user belongs to a second group");
        Files.setPosixFilePermissions(keystore, GROUP_READ);

        KeyStoreFiles.write(keystore, out -> out.write(bytes("new keys")));
        assertEquals(other.get(), Files.readAttributes(keystore, PosixFileAttributes.class).group(), "the operator's group is kept");
        assertEquals(GROUP_READ, Files.getPosixFilePermissions(keystore));
    }

    /**
     * Native ACLs Java cannot see (macOS {@code chmod +a}, Linux {@code setfacl}) survive the write, since the file is
     * rewritten in place; a replacement by another file would have dropped them.
     */
    @Test
    void nativeAclsJavaCannotSeeAreKept() throws Exception {
        Path keystore = Files.write(dir.resolve("issuer.p12"), bytes("old"));
        Files.setPosixFilePermissions(keystore, OWNER_ONLY);
        String file = keystore.toString();
        boolean mac = System.getProperty("os.name", "").toLowerCase().contains("mac");
        if (mac) {
            assumeTrue(run("chmod", "+a", "everyone allow readextattr", file).isPresent(), "chmod +a works here");
        } else {
            assumeTrue(run("setfacl", "-m", "u:65534:r", file).isPresent(), "setfacl works here");
        }
        String before = acl(keystore, mac);
        assumeTrue(before.contains(mac ? "allow readextattr" : ":65534:r") || before.contains("nobody:r"), "the ACL was set: " + before);

        KeyStoreFiles.write(keystore, out -> out.write(bytes("new keys")));

        assertArrayEquals(bytes("new keys"), Files.readAllBytes(keystore));
        assertEquals(before, acl(keystore, mac), "the native ACL is unchanged");
    }

    @Test
    void aSymlinkChainIsKeptAndTheFileItNamesIsRewritten() throws Exception {
        Path secrets = Files.createDirectories(dir.resolve("secrets"));
        Path real = Files.write(secrets.resolve("keystore.p12"), bytes("old"));
        Files.setPosixFilePermissions(real, GROUP_READ);
        Path config = Files.createDirectories(dir.resolve("config"));
        Path middle = Files.createSymbolicLink(config.resolve("current.p12"), Path.of("..", "secrets", "keystore.p12"));
        Path link = Files.createSymbolicLink(config.resolve("issuer.p12"), Path.of("current.p12"));

        KeyStoreFiles.write(link, out -> out.write(bytes("new keys")));

        assertTrue(Files.isSymbolicLink(link) && Files.isSymbolicLink(middle), "both links are kept");
        assertEquals(Path.of("current.p12"), Files.readSymbolicLink(link));
        assertEquals(Path.of("..", "secrets", "keystore.p12"), Files.readSymbolicLink(middle));
        assertArrayEquals(bytes("new keys"), Files.readAllBytes(real), "the file they name is rewritten");
        assertEquals(GROUP_READ, Files.getPosixFilePermissions(real));
        assertEquals(List.of("current.p12", "issuer.p12"), listing(config), "nothing written beside the links");
        assertEquals(List.of("keystore.p12", "keystore.p12.bak"), listing(secrets), "the backup sits beside the real file");

        Path dangling = Files.createSymbolicLink(config.resolve("next.p12"), Path.of("..", "secrets", "next.p12"));
        KeyStoreFiles.write(dangling, out -> out.write(bytes("first keys")));
        assertTrue(Files.isSymbolicLink(dangling), "a link to a file not yet written is kept too");
        assertArrayEquals(bytes("first keys"), Files.readAllBytes(secrets.resolve("next.p12")));
        assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(secrets.resolve("next.p12"), LinkOption.NOFOLLOW_LINKS));
    }

    /**
     * Review round 2, item 4: a dangling relative link reached through a symlinked directory resolves against the link's
     * real directory, as the operating system resolves it, not against the symlinked path.
     */
    @Test
    void aDanglingLinkThroughASymlinkedDirectoryResolvesLikeTheOperatingSystem() throws Exception {
        Path deep = Files.createDirectories(dir.resolve("a").resolve("b"));
        Path keys = Files.createDirectories(dir.resolve("a").resolve("keys"));
        Path link = Files.createSymbolicLink(deep.resolve("next.p12"), Path.of("..", "keys", "next.p12"));
        Path shortcut = Files.createSymbolicLink(dir.resolve("l"), Path.of("a", "b"));

        KeyStoreFiles.write(shortcut.resolve("next.p12"), out -> out.write(bytes("first keys")));

        assertArrayEquals(bytes("first keys"), Files.readAllBytes(keys.resolve("next.p12")), "written where the link points");
        assertTrue(Files.isSymbolicLink(link));
        assertFalse(Files.exists(dir.resolve("keys")), "not under the symlinked path's parent");
        assertArrayEquals(bytes("first keys"), Files.readAllBytes(shortcut.resolve("next.p12")));
    }

    @Test
    void aLinkLoopIsRefusedAndKept() throws Exception {
        Path a = dir.resolve("a.p12");
        Path b = dir.resolve("b.p12");
        Files.createSymbolicLink(a, b.getFileName());
        Files.createSymbolicLink(b, a.getFileName());

        assertThrows(FileSystemLoopException.class, () -> KeyStoreFiles.write(a, out -> out.write(bytes("keys"))));
        assertTrue(Files.isSymbolicLink(a) && Files.isSymbolicLink(b), "neither link is replaced by a file");
        assertEquals(List.of("a.p12", "b.p12"), listing(dir));
    }

    @Test
    void aDirectoryTheServiceMayNotWriteStillLetsAnExistingKeystoreBeRewritten() throws Exception {
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
            assertEquals(List.of("issuer.p12"), listing(locked), "no room for a backup: written without one (a warning says so)");

            assertThrows(AccessDeniedException.class, () -> KeyStoreFiles.write(locked.resolve("new.p12"), out -> out.write(bytes("x"))),
                    "a new keystore in a directory the service may not write cannot be created at all");
        } finally {
            Files.setPosixFilePermissions(locked, PosixFilePermissions.fromString("rwx------"));
        }
    }

    /** A keystore the operator made read-only ({@code r--------}) is not written, and no backup is made. */
    @Test
    void aReadOnlyKeystoreIsLeftAlone() throws Exception {
        Path keystore = Files.write(dir.resolve("issuer.p12"), bytes("old"));
        Files.setPosixFilePermissions(keystore, PosixFilePermissions.fromString("r--------"));
        try {
            assumeFalse(Files.isWritable(keystore), "not running as root");
            assertThrows(AccessDeniedException.class, () -> KeyStoreFiles.write(keystore, out -> out.write(bytes("new keys"))));
            assertArrayEquals(bytes("old"), Files.readAllBytes(keystore));
            assertEquals(PosixFilePermissions.fromString("r--------"), Files.getPosixFilePermissions(keystore));
            assertEquals(List.of("issuer.p12"), listing(dir), "no backup, no temporary file");
        } finally {
            Files.setPosixFilePermissions(keystore, OWNER_ONLY);
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

    /** The native ACL as the platform's own tool prints it (the file name line excluded). */
    static String acl(Path file, boolean mac) throws Exception {
        String out = (mac ? run("ls", "-le", file.toString()) : run("getfacl", "-c", file.toString())).orElseThrow();
        return Arrays.stream(out.split("\n")).filter(line -> mac ? line.matches("\\s*\\d+: .*") : !line.isBlank())
                .reduce("", (a, b) -> a + b.trim() + "\n");
    }

    /** Runs a command, its output when it exits 0. */
    static Optional<String> run(String... command) {
        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0 ? Optional.of(out) : Optional.empty();
        } catch (IOException e) {
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }
}
