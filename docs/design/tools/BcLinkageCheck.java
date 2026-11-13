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
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * BouncyCastle linkage guard (decision log 2026-11-13, F-10): every {@code org/bouncycastle} class, method and field
 * that the compiled classes reference must resolve, with the same descriptor, against the BouncyCastle jars given
 * (1.69, which published plugin jars put first on {@code loader.path}). This covers code that no test reaches; the
 * {@code bc169} Maven profile covers behaviour.
 *
 * <p>Usage: {@code java BcLinkageCheck.java <bc jar>[:<bc jar>...] <classes dir>...}; exit 0 when everything links,
 * 1 with one line per unresolved reference otherwise.
 */
public class BcLinkageCheck {

    record Ref(String kind, String owner, String name, String descriptor) {
        @Override
        public String toString() {
            return kind.equals("class") ? owner : owner + "." + name + ":" + descriptor;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: BcLinkageCheck <bc jar>[:<bc jar>...] <classes dir>...");
            System.exit(2);
        }
        URL[] jars = Arrays.stream(args[0].split(java.io.File.pathSeparator)).map(BcLinkageCheck::url).toArray(URL[]::new);
        ClassLoader bouncyCastle = new URLClassLoader(jars, ClassLoader.getPlatformClassLoader());
        Set<String> problems = new TreeSet<>();
        int classes = 0;
        int references = 0;
        for (int i = 1; i < args.length; i++) {
            Path dir = Path.of(args[i]);
            List<Path> files;
            try (Stream<Path> walk = Files.walk(dir)) {
                files = walk.filter(p -> p.toString().endsWith(".class")).sorted().toList();
            }
            for (Path file : files) {
                classes++;
                for (Ref ref : references(file)) {
                    references++;
                    String problem = resolve(bouncyCastle, ref);
                    if (problem != null) {
                        problems.add(ref.kind() + " " + ref + " (" + problem + ") used by " + dir.relativize(file));
                    }
                }
            }
        }
        problems.forEach(p -> System.out.println("UNRESOLVED " + p));
        System.out.println(classes + " classes, " + references + " BouncyCastle references, " + problems.size() + " unresolved against "
                + Arrays.toString(Arrays.stream(jars).map(u -> Path.of(u.getPath()).getFileName().toString()).toArray()));
        System.exit(problems.isEmpty() ? 0 : 1);
    }

    static URL url(String path) {
        try {
            return Path.of(path).toUri().toURL();
        } catch (IOException e) {
            throw new IllegalArgumentException(path, e);
        }
    }

    /** The org/bouncycastle Class, Fieldref, Methodref and InterfaceMethodref entries of a class file's constant pool. */
    static List<Ref> references(Path file) throws IOException {
        try (InputStream raw = Files.newInputStream(file); DataInputStream in = new DataInputStream(raw)) {
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
