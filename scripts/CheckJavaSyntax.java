import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import javax.tools.*;
import com.sun.source.util.JavacTask;

/** Trusted parser driver. Parses only: no analysis, processors, generation or target execution. */
class CheckJavaSyntax {
    public static void main(String[] args) throws Exception {
        var files = new ArrayList<java.io.File>();
        try (var paths = Files.walk(Path.of(args[0]))) {
            paths.filter(path -> path.toString().endsWith(".java")).forEach(path -> files.add(path.toFile()));
        }
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("A JDK is required");
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        try (var manager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {
            var task = (JavacTask) compiler.getTask(null, manager, diagnostics, List.of("-proc:none", "--release", "17"), null, manager.getJavaFileObjectsFromFiles(files));
            task.parse();
        }
        var errors = diagnostics.getDiagnostics().stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).toList();
        errors.forEach(System.err::println);
        System.out.println("Parsed " + files.size() + " Java sources; syntax errors: " + errors.size() + ". No type check or target execution.");
        if (!errors.isEmpty()) System.exit(1);
    }
}
