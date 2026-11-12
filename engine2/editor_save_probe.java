import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

// Java NIO operations used by IDEs, against disposable files only.
class EditorSaveProbe {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]);
        var executor = Executors.newFixedThreadPool(8);
        var tasks = new ArrayList<Future<?>>();
        try {
            for (int index = 0; index < 8; index++) {
                final int id = index;
                tasks.add(executor.submit(() -> {
                    try {
                        Path target = root.resolve("Jvm" + id + ".java");
                        for (int turn = 0; turn < 8; turn++) {
                            byte[] original = ("class Before" + id + " {}\n").getBytes(StandardCharsets.UTF_8);
                            Files.write(target, original);
                            String tempSuffix = turn % 2 == 0 ? ".tmp" : "___jb_tmp___";
                            String backupSuffix = turn % 2 == 0 ? "~" : "___jb_old___";
                            Path temp = root.resolve(target.getFileName() + tempSuffix);
                            Path backup = root.resolve(target.getFileName() + backupSuffix);
                            byte[] expected = ("// 保存 " + id + ":" + turn + "\n").repeat(500).getBytes(StandardCharsets.UTF_8);
                            Files.write(temp, expected, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                                        StandardOpenOption.WRITE, StandardOpenOption.SYNC);
                            try (var channel = FileChannel.open(target, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                                var mapped = channel.map(FileChannel.MapMode.READ_ONLY, 0, original.length);
                                Files.move(target, backup, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                                var read = ByteBuffer.allocate(original.length);
                                while (read.hasRemaining()) {
                                    if (channel.read(read) < 0) throw new AssertionError("short read after rename");
                                }
                                if (!Arrays.equals(read.array(), original)) throw new AssertionError("renamed descriptor changed view");
                                byte[] mappedBytes = new byte[original.length];
                                mapped.get(mappedBytes);
                                if (!Arrays.equals(mappedBytes, original)) throw new AssertionError("renamed mmap changed view");
                                channel.write(ByteBuffer.wrap(new byte[]{'/', '/'}), 0);
                                channel.truncate(original.length);
                                channel.force(true);
                                Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                            }
                            Files.delete(backup);
                            if (!Arrays.equals(Files.readAllBytes(target), expected)) throw new AssertionError("safe save changed content");
                        }
                        try (var channel = FileChannel.open(target, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                            var mapped = channel.map(FileChannel.MapMode.READ_WRITE, 0, channel.size());
                            mapped.put(0, (byte)'/');
                            mapped.put(1, (byte)'/');
                            mapped.force();
                        }
                    } catch (Exception error) {
                        throw new RuntimeException(error);
                    }
                }));
            }
            for (var task : tasks) task.get();
        } finally {
            executor.shutdownNow();
        }
        System.out.println("PASS Java NIO: 64 parallel safe saves, renamed descriptors and mmap");
    }
}
