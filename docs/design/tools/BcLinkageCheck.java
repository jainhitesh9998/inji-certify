import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * BouncyCastle linkage guard (decision log 2026-11-13, F-10): every {@code org/bouncycastle} class, method and field
 * that the given classes reference must resolve, with the same descriptor, against the BouncyCastle jars given
 * (1.69, which published plugin jars put first on {@code loader.path}). This covers code that no test reaches; the
 * {@code bc169} Maven profile covers behaviour.
 *
 * <p>Usage: {@code java BcLinkageCheck.java <bc jar>[:<bc jar>...] [--allow <file>] <classes dir or jar>...}. Classes
 * under {@code org/bouncycastle/} inside a checked jar are BouncyCastle itself and are skipped. An allowlist line is
 * {@code <location regex> <using class regex> <reference regex> <reason>}: the location is a jar's file name or a
 * classes directory as given, the using class is in internal form ({@code a/b/C}), the reference is printed as below;
 * an unresolved reference that a line matches is reported as ALLOWED with its reason, and a line that matches nothing
 * is reported as UNUSED (a note, not a failure). Exit 0 when every reference resolves or is allowed, 1 with one
 * UNRESOLVED line per other reference.
 */
public class BcLinkageCheck {

    record Ref(String kind, String owner, String name, String descriptor) {
        @Override
        public String toString() {
            return kind.equals("class") ? owner : owner + "." + name + ":" + descriptor;
        }
    }

    record Rule(Pattern location, Pattern user, Pattern reference, String reason, String line) {
        boolean matches(String where, String userClass, Ref ref) {
            return location.matcher(where).matches() && user.matcher(userClass).matches() && reference.matcher(ref.toString()).matches();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: BcLinkageCheck <bc jar>[:<bc jar>...] [--allow <file>] <classes dir or jar>...");
            System.exit(2);
        }
        URL[] jars = Arrays.stream(args[0].split(java.io.File.pathSeparator)).map(BcLinkageCheck::url).toArray(URL[]::new);
        ClassLoader bouncyCastle = new URLClassLoader(jars, ClassLoader.getPlatformClassLoader());
        List<Rule> rules = new ArrayList<>();
        int first = 1;
        if (args.length > 2 && args[1].equals("--allow")) {
            rules = rules(Path.of(args[2]));
            first = 3;
        }
        Set<String> problems = new TreeSet<>();
        Set<String> allowed = new TreeSet<>();
        Set<Rule> used = new HashSet<>();
        int classes = 0;
        int references = 0;
        int locations = 0;
        for (int i = first; i < args.length; i++) {
            Path location = Path.of(args[i]);
            String where = Files.isDirectory(location) ? args[i] : location.getFileName().toString();
            locations++;
            for (Map.Entry<String, byte[]> type : classFiles(location).entrySet()) {
                classes++;
                String userClass = type.getKey().replaceFirst("\\.class$", "").replaceFirst("^META-INF/versions/\\d+/", "");
                for (Ref ref : references(type.getKey(), type.getValue())) {
                    references++;
                    String problem = resolve(bouncyCastle, ref);
                    if (problem == null) {
                        continue;
                    }
                    String line = ref.kind() + " " + ref + " (" + problem + ") used by " + where + "!/" + type.getKey();
                    Rule rule = rules.stream().filter(r -> r.matches(where, userClass, ref)).findFirst().orElse(null);
                    if (rule == null) {
                        problems.add(line);
                    } else {
                        used.add(rule);
                        allowed.add(line + ": " + rule.reason());
                    }
                }
            }
        }
        allowed.forEach(p -> System.out.println("ALLOWED " + p));
        rules.stream().filter(r -> !used.contains(r)).forEach(r -> System.out.println("UNUSED allowlist line (nothing matches it): " + r.line()));
        problems.forEach(p -> System.out.println("UNRESOLVED " + p));
        System.out.println(locations + " locations, " + classes + " classes, " + references + " BouncyCastle references, "
                + allowed.size() + " allowed, " + problems.size() + " unresolved against "
                + Arrays.toString(Arrays.stream(jars).map(u -> Path.of(u.getPath()).getFileName().toString()).toArray()));
        System.exit(problems.isEmpty() ? 0 : 1);
    }

    static List<Rule> rules(Path file) throws IOException {
        List<Rule> rules = new ArrayList<>();
        for (String raw : Files.readAllLines(file)) {
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] columns = line.split("\\s+", 4);
            if (columns.length < 4) {
                throw new IllegalArgumentException(file + ": an allowlist line needs a location, a using class, a reference and a reason: " + line);
            }
            rules.add(new Rule(Pattern.compile(columns[0]), Pattern.compile(columns[1]), Pattern.compile(columns[2]), columns[3], line));
        }
        return rules;
    }

    /** The class files of a directory or a jar, by path inside it; BouncyCastle's own classes bundled in a jar are left out. */
    static Map<String, byte[]> classFiles(Path location) throws IOException {
        Map<String, byte[]> files = new TreeMap<>();
        if (Files.isDirectory(location)) {
            try (Stream<Path> walk = Files.walk(location)) {
                for (Path file : walk.filter(p -> p.toString().endsWith(".class")).sorted().toList()) {
                    files.put(location.relativize(file).toString().replace(java.io.File.separatorChar, '/'), Files.readAllBytes(file));
                }
            }
            return files;
        }
        try (ZipFile zip = new ZipFile(location.toFile())) {
            for (ZipEntry entry : java.util.Collections.list(zip.entries())) {
                String name = entry.getName();
                if (entry.isDirectory() || !name.endsWith(".class") || name.replaceFirst("^META-INF/versions/\\d+/", "").startsWith("org/bouncycastle/")) {
                    continue;
                }
                try (InputStream in = zip.getInputStream(entry)) {
                    files.put(name, in.readAllBytes());
                }
            }
        }
        return files;
    }

    static URL url(String path) {
        try {
            return Path.of(path).toUri().toURL();
        } catch (IOException e) {
            throw new IllegalArgumentException(path, e);
        }
    }

    /** The org/bouncycastle Class, Fieldref, Methodref and InterfaceMethodref entries of a class file's constant pool. */
    static List<Ref> references(String file, byte[] bytes) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (in.readInt() != 0xCAFEBABE) {
                throw new IOException(file + " is not a class file");
            }
            in.readUnsignedShort();
            in.readUnsignedShort();
            int count = in.readUnsignedShort();
            String[] utf8 = new String[count];
            int[] tag = new int[count];
            int[] a = new int[count];
            int[] b = new int[count];
            for (int i = 1; i < count; i++) {
                tag[i] = in.readUnsignedByte();
                switch (tag[i]) {
                    case 1 -> utf8[i] = in.readUTF();
                    case 3, 4 -> in.readInt();
                    case 5, 6 -> { in.readLong(); i++; }
                    case 7, 8, 16, 19, 20 -> a[i] = in.readUnsignedShort();
                    case 9, 10, 11, 12, 17, 18 -> { a[i] = in.readUnsignedShort(); b[i] = in.readUnsignedShort(); }
                    case 15 -> { in.readUnsignedByte(); a[i] = in.readUnsignedShort(); }
                    default -> throw new IOException(file + ": constant pool tag " + tag[i]);
                }
            }
            List<Ref> refs = new ArrayList<>();
            for (int i = 1; i < count; i++) {
                if (tag[i] == 7) {
                    String name = utf8[a[i]];
                    String element = name.replaceFirst("^\\[+L(.*);$", "$1");
                    if (element.startsWith("org/bouncycastle/")) {
                        refs.add(new Ref("class", element, null, null));
                    }
                } else if (tag[i] == 9 || tag[i] == 10 || tag[i] == 11) {
                    String owner = utf8[a[a[i]]];
                    if (owner.startsWith("org/bouncycastle/")) {
                        int nameAndType = b[i];
                        refs.add(new Ref(tag[i] == 9 ? "field" : "method", owner, utf8[a[nameAndType]], utf8[b[nameAndType]]));
                    }
                }
            }
            return refs;
        }
    }

    /** Null when the reference resolves as the JVM would resolve it (superclasses, then superinterfaces), else why not. */
    static String resolve(ClassLoader loader, Ref ref) {
        Class<?> owner;
        try {
            owner = Class.forName(ref.owner().replace('/', '.'), false, loader);
        } catch (ClassNotFoundException | LinkageError e) {
            return "class missing";
        }
        if (ref.kind().equals("class")) {
            return null;
        }
        if (ref.kind().equals("field")) {
            for (Class<?> type : hierarchy(owner)) {
                for (Field field : type.getDeclaredFields()) {
                    if (field.getName().equals(ref.name()) && MethodType.methodType(field.getType()).toMethodDescriptorString().substring(2).equals(ref.descriptor())) {
                        return null;
                    }
                }
            }
            return "field missing";
        }
        if (ref.name().equals("<init>")) {
            for (Constructor<?> constructor : owner.getDeclaredConstructors()) {
                if (MethodType.methodType(void.class, constructor.getParameterTypes()).toMethodDescriptorString().equals(ref.descriptor())) {
                    return null;
                }
            }
            return "constructor missing";
        }
        List<Class<?>> types = hierarchy(owner);
        types.add(Object.class);
        for (Class<?> type : types) {
            for (Method method : type.getDeclaredMethods()) {
                if (method.getName().equals(ref.name())
                        && MethodType.methodType(method.getReturnType(), method.getParameterTypes()).toMethodDescriptorString().equals(ref.descriptor())) {
                    return null;
                }
            }
        }
        return "method missing";
    }

    static List<Class<?>> hierarchy(Class<?> type) {
        List<Class<?>> out = new ArrayList<>();
        Set<Class<?>> seen = new HashSet<>();
        Deque<Class<?>> todo = new ArrayDeque<>();
        todo.add(type);
        while (!todo.isEmpty()) {
            Class<?> next = todo.poll();
            if (!seen.add(next)) {
                continue;
            }
            out.add(next);
            if (next.getSuperclass() != null) {
                todo.add(next.getSuperclass());
            }
            todo.addAll(Arrays.asList(next.getInterfaces()));
        }
        return out;
    }
}
