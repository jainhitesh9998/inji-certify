package io.mosip.certify.keyprovider.jca;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystemException;
import java.nio.file.FileSystemLoopException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Set;

/**
 * Writes a file that holds private keys (decision log 2026-11-13, F-10 review rounds 1 and 2):
 * <ul>
 *     <li>a <b>new</b> file is written to a temporary file in its directory, created {@code rw-------} (POSIX; the mode is
 *     given at creation, so the umask can only narrow it and the keys are never readable by others, not even while being
 *     written), forced to disk and moved into place atomically;</li>
 *     <li>an <b>existing</b> file is rewritten <b>in place</b> (truncated, written, forced to disk), so it keeps every
 *     attribute the file system gives it: owner, group, permissions, and the native ACLs and extended attributes Java
 *     cannot see (macOS ACLs, Linux POSIX ACLs set with {@code setfacl}, which a replacement by another file would drop;
 *     CLAUDE.md rule 3). Before that, the previous content is saved as the sibling {@code <file>.bak}: written to a
 *     temporary file created {@code rw-------}, forced to disk and moved over the previous backup atomically, so a crash
 *     during the in-place write leaves the previous keystore whole in the backup. A directory the service may not write
 *     (or a keystore bind-mounted as a single file) leaves no room for the backup: the file is still rewritten in place,
 *     without one, with a warning. A file the service may not write (made read-only, {@code r--------}) is not written:
 *     {@code AccessDeniedException}, the file and any backup untouched;</li>
 *     <li>a symbolic link is followed, through any chain of links and symlinked directories: the file it names is written
 *     and the links are kept; a link loop is refused with {@link FileSystemLoopException}, never replaced by a file.</li>
 * </ul>
 * On a file system without POSIX permissions a new file (and a backup) is written all the same and a warning asks the
 * operator to restrict it.
 */
public final class KeyStoreFiles {

    private static final System.Logger LOG = System.getLogger(KeyStoreFiles.class.getName());

    static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");
    static final String BACKUP_SUFFIX = ".bak";
    private static final int MAX_LINKS = 40;

    /** What {@link #write} writes into the file. */
    @FunctionalInterface
    public interface Content {
        void writeTo(OutputStream out) throws IOException, GeneralSecurityException;
    }

    private KeyStoreFiles() {}

    public static void write(Path path, Content content) throws IOException, GeneralSecurityException {
        ByteArrayOutputStream rendered = new ByteArrayOutputStream();
        content.writeTo(rendered); // before any file is touched: a failure here leaves the previous file as it was
        byte[] bytes = rendered.toByteArray();

        Path target = realTarget(path);
        Path directory = target.getParent();
        boolean exists = Files.exists(target);
        boolean posix = Files.getFileStore(exists ? target : directory).supportsFileAttributeView(PosixFileAttributeView.class);
        if (exists) {
            warnIfReadableByOthers(target, posix);
            rewriteInPlace(target, bytes, posix);
        } else {
            if (!posix) {
                LOG.log(System.Logger.Level.WARNING,
                        "{0} holds private keys but its file system has no POSIX permissions; restrict access to it", target);
            }
            create(target, bytes, posix);
        }
    }

    /** The backup kept beside an existing keystore: the content it had before the last write. */
    public static Path backupOf(Path keystore) {
        return keystore.resolveSibling(keystore.getFileName().toString() + BACKUP_SUFFIX);
    }

    /**
     * The file a path names: the path itself, or, through any symbolic links, the file they lead to (which may not
     * exist yet), so the links are kept and the file is written where they point. A relative link target is resolved
     * against the real directory of the link (so a link reached through a symlinked directory resolves as the operating
     * system resolves it).
     *
     * @throws FileSystemLoopException when the links form a loop (or a chain longer than 40 links)
     */
    static Path realTarget(Path path) throws IOException {
        Path current = path.toAbsolutePath();
        Set<Path> seen = new HashSet<>();
        for (int hops = 0; Files.isSymbolicLink(current); hops++) {
            if (Files.exists(current)) {
                return current.toRealPath();
            }
            if (hops >= MAX_LINKS || !seen.add(current)) {
                throw new FileSystemLoopException(path.toString());
            }
            current = current.getParent().toRealPath().resolve(Files.readSymbolicLink(current)).normalize();
        }
        return Files.exists(current) ? current.toRealPath() : current;
    }

    /**
     * An existing keystore: the previous content saved as {@code <file>.bak}, then the file itself truncated and
     * rewritten, keeping every attribute it has. The file is opened for writing first, so one the service may not write
     * fails before anything (the backup included) is touched.
     */
    private static void rewriteInPlace(Path target, byte[] bytes, boolean posix) throws IOException {
        try (FileChannel channel = FileChannel.open(target, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            backup(target, channel, posix);
            channel.truncate(0);
            channel.position(0);
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
    }

    /** Saves the file's current content as {@code <file>.bak} ({@code rw-------}, forced, moved atomically); a warning when it cannot. */
    private static void backup(Path target, FileChannel channel, boolean posix) {
        Path backup = backupOf(target);
        Path temporary = null;
        try {
            byte[] previous = readAll(channel);
            temporary = temporaryFile(target, posix);
            writeAndForce(temporary, previous, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            move(temporary, backup);
            temporary = null;
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            LOG.log(System.Logger.Level.WARNING, "{0} is rewritten in place without a backup: {1} cannot be written ({2}); "
                    + "a crash during the write would leave the keystore incomplete", target, backup, e.toString());
        } finally {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException e) {
                    LOG.log(System.Logger.Level.WARNING, "Temporary file {0} could not be removed: {1}", temporary, e.toString());
                }
            }
        }
    }

    /** A new keystore: a temporary file created {@code rw-------}, forced and moved into place atomically. */
    private static void create(Path target, byte[] bytes, boolean posix) throws IOException {
        Path temporary;
        try {
            temporary = temporaryFile(target, posix);
        } catch (FileSystemException e) {
            createInPlace(target, bytes, posix, "a temporary file cannot be created in " + target.getParent(), e);
            return;
        }
        try {
            writeAndForce(temporary, bytes, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                move(temporary, target);
            } catch (FileSystemException e) {
                createInPlace(target, bytes, posix, "it cannot be moved into place", e);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static Path temporaryFile(Path target, boolean posix) throws IOException {
        Path directory = target.getParent();
        String prefix = target.getFileName().toString();
        return posix
                ? Files.createTempFile(directory, prefix, ".tmp", PosixFilePermissions.asFileAttribute(OWNER_ONLY))
                : Files.createTempFile(directory, prefix, ".tmp");
    }

    private static void move(Path temporary, Path target) throws IOException {
        try {
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** A new file written directly, created {@code rw-------} (exclusively: an existing file is never overwritten here). */
    private static void createInPlace(Path target, byte[] bytes, boolean posix, String why, Exception cause) throws IOException {
        LOG.log(System.Logger.Level.WARNING, "{0} is written directly, not moved into place: {1} ({2})", target, why, cause.toString());
        try {
            if (posix) {
                writeAndForce(target, bytes, PosixFilePermissions.asFileAttribute(OWNER_ONLY), StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
            } else {
                writeAndForce(target, bytes, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
            }
        } catch (IOException e) {
            e.addSuppressed(cause);
            throw e;
        }
    }

    private static byte[] readAll(FileChannel channel) throws IOException {
        long size = channel.size();
        if (size > Integer.MAX_VALUE - 8) {
            throw new IOException("File too large to back up: " + size + " bytes");
        }
        ByteBuffer buffer = ByteBuffer.allocate((int) size);
        long position = 0;
        while (buffer.hasRemaining()) {
            int n = channel.read(buffer, position);
            if (n < 0) {
                break;
            }
            position += n;
        }
        return buffer.array();
    }

    private static void writeAndForce(Path file, byte[] bytes, OpenOption... options) throws IOException {
        writeAndForce(file, bytes, null, options);
    }

    private static void writeAndForce(Path file, byte[] bytes, FileAttribute<?> attribute, OpenOption... options) throws IOException {
        Set<OpenOption> open = Set.of(options);
        try (FileChannel channel = attribute == null ? FileChannel.open(file, open) : FileChannel.open(file, open, attribute)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
    }

    private static void warnIfReadableByOthers(Path target, boolean posix) {
        if (!posix) {
            return;
        }
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS);
            if (permissions.contains(PosixFilePermission.OTHERS_READ)) {
                LOG.log(System.Logger.Level.WARNING, "{0} holds private keys and is readable by every user ({1}); it keeps its "
                        + "permissions, restrict them with chmod o-r", target, PosixFilePermissions.toString(permissions));
            }
        } catch (IOException e) {
            // the warning is advice only
        }
    }
}
