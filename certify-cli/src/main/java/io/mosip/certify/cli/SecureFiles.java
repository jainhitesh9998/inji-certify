package io.mosip.certify.cli;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.FileAlreadyExistsException;
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
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * How the CLI touches the filesystem: every keystore, private key, CRL state, certificate and CRL is written to a
 * temporary file in the target's directory, flushed to disk and renamed over the target in one atomic step, so a crash
 * leaves either the old file or the new one, never a torn one. Secrets (keystores, private keys, state) are created
 * {@code rw-------} at creation time, not chmod-ed afterwards; public objects (certificates, CRLs) are created
 * {@code rw-r--r--} minus the umask. Read-modify-write of a keystore or of CRL state happens under an exclusive lock on
 * a stable {@code <file>.lock} next to it, held across processes ({@link FileChannel#lock()}) and threads.
 *
 * <p>Before anything is written, a command passes its input and output paths to {@link #requireDistinct}: two names
 * for one file (the same path, a symbolic link, {@code ./x} and {@code x}, a hard link) are refused, so {@code --out}
 * can never overwrite the keystore or IACA it was computed from.
 */
final class SecureFiles {

    static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");
    static final Set<PosixFilePermission> PUBLIC = PosixFilePermissions.fromString("rw-r--r--");

    /** One in-JVM lock per lock file: {@link FileChannel#lock()} refuses a second lock from the same JVM. */
    private static final Map<Path, ReentrantLock> JVM_LOCKS = new ConcurrentHashMap<>();
    private static final Set<Path> WARNED = ConcurrentHashMap.newKeySet();

    /** Whether a written file holds a secret ({@code 0600}) or a public object ({@code 0644} minus the umask). */
    enum Visibility { SECRET, PUBLIC }

    private SecureFiles() {}

    // ------------------------------------------------------------------ paths

    /**
     * The canonical name of a path: the real path when it exists (symbolic links resolved), else the real path of its
     * nearest existing ancestor followed by the remaining names, so a file that is about to be created compares equal
     * to the same file named another way.
     */
    static Path canonical(Path path) throws IOException {
        Path absolute = path.toAbsolutePath().normalize();
        if (Files.exists(absolute)) {
            return absolute.toRealPath();
        }
        Deque<String> tail = new ArrayDeque<>();
        Path probe = absolute;
        while (probe != null && !Files.exists(probe)) {
            if (probe.getFileName() != null) {
                tail.addFirst(probe.getFileName().toString());
            }
            probe = probe.getParent();
        }
        Path base = probe == null ? absolute.getRoot() : probe.toRealPath();
        for (String name : tail) {
            base = base.resolve(name);
        }
        return base;
    }

    /** {@code <file>.lock} next to the canonical file; the lock file is created once and never removed. */
    static Path lockFile(Path target) throws IOException {
        Path canonical = canonical(target);
        return canonical.resolveSibling(canonical.getFileName() + ".lock");
    }

    /**
     * Refuses when an output names the same file as an input or another output. {@code inputs} and {@code outputs}
     * map an option label ({@code --out}, {@code -k}) to its path; {@code null} paths are skipped. Inputs may name one
     * file twice (reading it twice is harmless).
     */
    static void requireDistinct(Map<String, Path> inputs, Map<String, Path> outputs) throws IOException {
        record Named(String label, Path path, Path canonical, boolean output) {}
        List<Named> all = new ArrayList<>();
        for (Map.Entry<String, Path> input : inputs.entrySet()) {
            if (input.getValue() != null) {
                all.add(new Named(input.getKey(), input.getValue(), canonical(input.getValue()), false));
            }
        }
        for (Map.Entry<String, Path> output : outputs.entrySet()) {
            if (output.getValue() != null) {
                all.add(new Named(output.getKey(), output.getValue(), canonical(output.getValue()), true));
            }
        }
        for (int i = 0; i < all.size(); i++) {
            for (int j = i + 1; j < all.size(); j++) {
                Named a = all.get(i);
                Named b = all.get(j);
                if (!a.output() && !b.output()) {
                    continue;
                }
                if (a.canonical().equals(b.canonical()) || sameExistingFile(a.canonical(), b.canonical())) {
                    throw new UsageException(a.label() + " (" + a.path() + ") and " + b.label() + " ("
                            + b.path() + ") name the same file " + a.canonical() + "; refusing before anything is"
                            + " written");
                }
            }
        }
    }

    /** A convenience for {@link #requireDistinct}: an insertion-ordered map that accepts {@code null} values. */
    static Map<String, Path> paths(Object... labelsAndPaths) {
        Map<String, Path> map = new LinkedHashMap<>();
        for (int i = 0; i < labelsAndPaths.length; i += 2) {
            map.put((String) labelsAndPaths[i], (Path) labelsAndPaths[i + 1]);
        }
        return map;
    }

    private static boolean sameExistingFile(Path a, Path b) {
        try {
            return Files.exists(a) && Files.exists(b) && Files.isSameFile(a, b);
        } catch (IOException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ locks

    /** An exclusive lock on {@code <target>.lock}, across threads of this JVM and across processes. */
    static Lock lock(Path target) throws IOException {
        Path lockFile = lockFile(target);
        ReentrantLock jvmLock = JVM_LOCKS.computeIfAbsent(lockFile, path -> new ReentrantLock());
        jvmLock.lock();
        FileChannel channel = null;
        try {
            Files.createDirectories(lockFile.getParent());
            Set<OpenOption> options = Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            channel = posix(lockFile.getParent())
                    ? FileChannel.open(lockFile, options, PosixFilePermissions.asFileAttribute(OWNER_ONLY))
                    : FileChannel.open(lockFile, options);
            return new Lock(jvmLock, channel, channel.lock());
        } catch (IOException | RuntimeException e) {
            if (channel != null) {
                channel.close();
            }
            jvmLock.unlock();
            throw e;
        }
    }

    /** A held lock; closing it releases the file lock, the channel and the in-JVM lock. */
    static final class Lock implements AutoCloseable {
        private final ReentrantLock jvmLock;
        private final FileChannel channel;
        private final FileLock fileLock;

        private Lock(ReentrantLock jvmLock, FileChannel channel, FileLock fileLock) {
            this.jvmLock = jvmLock;
            this.channel = channel;
            this.fileLock = fileLock;
        }

        @Override
        public void close() throws IOException {
            try {
                fileLock.release();
            } finally {
                try {
                    channel.close();
                } finally {
                    jvmLock.unlock();
                }
            }
        }
    }

    // ------------------------------------------------------------------ writes

    /**
     * Writes {@code bytes} to {@code target}: a temporary file in the same directory created with the visibility's
     * permissions, forced to disk, then renamed over the target atomically. With {@code replace} false the target must
     * not exist: it is reserved with {@code CREATE_NEW} first, so two writers cannot both create it and an existing file
     * is refused ({@link FileAlreadyExistsException}) rather than replaced.
     */
    static void write(Path target, byte[] bytes, Visibility visibility, boolean replace) throws IOException {
        Path absolute = target.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        Files.createDirectories(parent);
        boolean posix = posix(parent);
        if (!posix) {
            warnNoPosix(parent);
        }
        FileAttribute<?>[] attributes = posix
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(
                        visibility == Visibility.SECRET ? OWNER_ONLY : PUBLIC)}
                : new FileAttribute<?>[0];
        Path temp = Files.createTempFile(parent, "." + absolute.getFileName() + ".", ".tmp", attributes);
        boolean reserved = false;
        boolean moved = false;
        try {
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            if (!replace) {
                Files.createFile(absolute, attributes); // CREATE_NEW: atomic, refuses an existing file
                reserved = true;
            }
            Files.move(temp, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            moved = true;
            forceDirectory(parent);
        } finally {
            Files.deleteIfExists(temp);
            if (reserved && !moved) {
                Files.deleteIfExists(absolute);
            }
        }
    }

    /** Whether the directory's file store supports POSIX permissions. */
    static boolean posix(Path directory) {
        try {
            Path probe = Files.exists(directory) ? directory : directory.getParent();
            return probe != null && Files.getFileStore(probe).supportsFileAttributeView(PosixFileAttributeView.class)
                    && Files.getFileAttributeView(probe, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS) != null;
        } catch (IOException e) {
            return false;
        }
    }

    private static void warnNoPosix(Path directory) {
        if (WARNED.add(directory)) {
            System.err.println("warning: " + directory + " does not support POSIX permissions; the files written there"
                    + " are not restricted to their owner, restrict access to them yourself");
        }
    }

    /** Best effort: make the rename durable; not every platform lets a directory be opened for a sync. */
    private static void forceDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | RuntimeException e) {
            // the rename is atomic either way; durability across a power loss is what is lost
        }
    }
}
