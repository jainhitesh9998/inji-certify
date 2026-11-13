package io.mosip.certify.keyprovider.jca;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Writes a file that holds private keys (decision log 2026-11-13, F-10 review round 1):
 * <ul>
 *     <li>a <b>new</b> file is created {@code rw-------} (POSIX; the mode is given at creation, so the umask can only
 *     narrow it and the keys are never readable by others, not even while being written);</li>
 *     <li>an <b>existing</b> file keeps its owner, group, permissions and, where the file system exposes them to Java
 *     ({@link AclFileAttributeView}), its ACL: an operator who set {@code rw-r-----} for a group, or handed the file to
 *     another account, finds it so after the upgrade (CLAUDE.md rule 3);</li>
 *     <li>a symbolic link is followed: the file it names is replaced and the link is kept;</li>
 *     <li>the content goes to a temporary file in the target's directory, is forced to disk and moved over the target
 *     atomically, so a crash leaves the previous file whole;</li>
 *     <li>when the temporary file cannot be created or moved ({@code AccessDeniedException} or another
 *     {@link FileSystemException}: a directory the service may not write, a keystore bind-mounted as a single file,
 *     whose replacement fails with {@code EBUSY}), or the existing owner, group or ACL cannot be given to it, the file is
 *     written in place (truncated and rewritten; an existing file keeps all its attributes) with a warning.</li>
 * </ul>
 * On a file system without POSIX permissions a new file is written all the same and a warning asks the operator to
 * restrict it. POSIX ACLs set with {@code setfacl} on Linux are not visible to Java and are not carried by the atomic
 * replacement.
 */
public final class KeyStoreFiles {

    private static final System.Logger LOG = System.getLogger(KeyStoreFiles.class.getName());

    static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");

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
        } else if (!posix) {
            LOG.log(System.Logger.Level.WARNING,
                    "{0} holds private keys but its file system has no POSIX permissions; restrict access to it", target);
        }

        Path temporary;
        try {
            temporary = posix
                    ? Files.createTempFile(directory, target.getFileName().toString(), ".tmp", PosixFilePermissions.asFileAttribute(OWNER_ONLY))
                    : Files.createTempFile(directory, target.getFileName().toString(), ".tmp");
        } catch (FileSystemException e) {
            inPlace(target, bytes, exists, posix, "a temporary file cannot be created in " + directory, e);
            return;
        }
        try {
            writeAndForce(temporary, bytes, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            if (exists) {
                try {
                    copyAttributes(target, temporary, posix);
                } catch (IOException | UnsupportedOperationException | SecurityException e) {
                    inPlace(target, bytes, true, posix, "its owner, group or ACL cannot be given to a replacement", e);
                    return;
                }
            }
            try {
                move(temporary, target);
            } catch (FileSystemException e) {
                inPlace(target, bytes, exists, posix, "it cannot be replaced by a move", e);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    /**
     * The file a path names: the path itself, or, through any symbolic links, the file they lead to (which may not
     * exist yet), so the link is kept and the temporary file lands in the real file's directory.
     */
    static Path realTarget(Path path) throws IOException {
        Path current = path.toAbsolutePath();
        for (int hops = 0; hops < 40 && Files.isSymbolicLink(current); hops++) {
            if (Files.exists(current)) {
                return current.toRealPath();
            }
            current = current.resolveSibling(Files.readSymbolicLink(current)).normalize();
        }
        return Files.exists(current) ? current.toRealPath() : current;
    }

    /** The existing file's owner, group and permissions (POSIX), or owner and ACL, given to the replacement before it is moved. */
    private static void copyAttributes(Path from, Path to, boolean posix) throws IOException {
        if (posix) {
            PosixFileAttributes existing = Files.readAttributes(from, PosixFileAttributes.class);
            PosixFileAttributeView replacement = Files.getFileAttributeView(to, PosixFileAttributeView.class);
            PosixFileAttributes current = replacement.readAttributes();
            if (!Objects.equals(existing.group(), current.group())) {
                replacement.setGroup(existing.group());
            }
            if (!Objects.equals(existing.owner(), current.owner())) {
                replacement.setOwner(existing.owner()); // only a privileged process can; otherwise the file is written in place
            }
            replacement.setPermissions(existing.permissions()); // after chown, which may clear bits
        }
        AclFileAttributeView acl = Files.getFileAttributeView(from, AclFileAttributeView.class);
        if (acl != null && Files.getFileStore(from).supportsFileAttributeView(AclFileAttributeView.class)) {
            List<AclEntry> entries = acl.getAcl();
            UserPrincipal owner = acl.getOwner();
            AclFileAttributeView replacement = Files.getFileAttributeView(to, AclFileAttributeView.class);
            if (!posix && !Objects.equals(owner, replacement.getOwner())) {
                replacement.setOwner(owner);
            }
            replacement.setAcl(entries);
        } else if (!posix) {
            FileOwnerAttributeView owner = Files.getFileAttributeView(from, FileOwnerAttributeView.class);
            if (owner != null) {
                FileOwnerAttributeView replacement = Files.getFileAttributeView(to, FileOwnerAttributeView.class);
                if (!Objects.equals(owner.getOwner(), replacement.getOwner())) {
                    replacement.setOwner(owner.getOwner());
                }
            }
        }
    }

    private static void move(Path temporary, Path target) throws IOException {
        try {
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** Truncates and rewrites the file itself: an existing file keeps every attribute, a new one is created {@code rw-------}. */
    private static void inPlace(Path target, byte[] bytes, boolean exists, boolean posix, String why, Exception cause) throws IOException {
        LOG.log(System.Logger.Level.WARNING, "{0} is written in place, not replaced atomically: {1} ({2})", target, why, cause.toString());
        try {
            if (exists) {
                writeAndForce(target, bytes, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            } else if (posix) {
                writeAndForce(target, bytes, PosixFilePermissions.asFileAttribute(OWNER_ONLY), StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
            } else {
                writeAndForce(target, bytes, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
            }
        } catch (IOException e) {
            e.addSuppressed(cause);
            throw e;
        }
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
