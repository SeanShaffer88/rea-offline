// Static Ghidra post-script. Never executes the imported target.
// @category REA.Forensics
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportForensic extends GhidraScript {
    private long bytes = 0;
    private static final long MAX_BYTES = 64L * 1024 * 1024;
    private String quote(String value) {
        if (value == null) return "null";
        StringBuilder result = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\': result.append("\\\\"); break;
                case '"': result.append("\\\""); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 32) result.append(String.format("\\u%04x", (int)c));
                    else result.append(c);
            }
        }
        return result.append('"').toString();
    }
    private boolean record(BufferedWriter writer, String line) throws IOException {
        long size = line.getBytes(StandardCharsets.UTF_8).length + 1;
        if (bytes + size > MAX_BYTES) return false;
        writer.write(line); writer.newLine(); bytes += size;
        return true;
    }
    private String calls(Set<Function> functions) {
        List<Function> sorted = new ArrayList<>(functions);
        sorted.sort(Comparator.comparing(f -> f.getEntryPoint().toString()));
        StringJoiner result = new StringJoiner(",", "[", "]");
        for (Function f : sorted.subList(0, Math.min(500, sorted.size()))) {
            result.add("{\"name\":" + quote(f.getName()) + ",\"address\":" + quote(f.getEntryPoint().toString()) + "}");
        }
        return result.toString();
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("output JSONL path required");
        int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 2000;
        if (maxFunctions < 1 || maxFunctions > 100000) throw new IllegalArgumentException("invalid function limit");
        File destination = new File(args[0]);
        // Refuse overwrite; keep partial JSONL if headless analysis is stopped.
        if (!destination.createNewFile()) throw new IOException("output already exists");
        DecompInterface decompiler = new DecompInterface();
        boolean opened = decompiler.openProgram(currentProgram);
        int processed = 0, failures = 0, instructionTruncations = 0;
        boolean byteLimit = false, symbolLimit = false;
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(destination), StandardCharsets.UTF_8))) {
            record(writer, "{\"kind\":\"program\",\"source_sha256\":" + quote(currentProgram.getExecutableSHA256())
                + ",\"image_base\":" + quote(currentProgram.getImageBase().toString())
                + ",\"language\":" + quote(currentProgram.getLanguageID().toString())
                + ",\"compiler\":" + quote(currentProgram.getCompilerSpec().getCompilerSpecID().toString())
                + ",\"functions_discovered\":" + currentProgram.getFunctionManager().getFunctionCount()
                + ",\"max_functions\":" + maxFunctions + ",\"max_bytes\":" + MAX_BYTES + "}");
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                if (!record(writer, "{\"kind\":\"memory_block\",\"name\":" + quote(block.getName())
                    + ",\"start\":" + quote(block.getStart().toString()) + ",\"size\":" + block.getSize()
                    + ",\"read\":" + block.isRead() + ",\"write\":" + block.isWrite()
                    + ",\"execute\":" + block.isExecute() + "}")) { byteLimit = true; break; }
            }
            SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            int symbolCount = 0;
            while (!byteLimit && symbols.hasNext()) {
                if (symbolCount++ == 10000) { symbolLimit = true; break; }
                Symbol symbol = symbols.next();
                if (!record(writer, "{\"kind\":\"symbol\",\"name\":" + quote(symbol.getName(true))
                    + ",\"address\":" + quote(symbol.getAddress().toString())
                    + ",\"type\":" + quote(symbol.getSymbolType().toString())
                    + ",\"external\":" + symbol.isExternal() + "}")) { byteLimit = true; }
            }
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (!byteLimit && functions.hasNext() && processed < maxFunctions && !monitor.isCancelled()) {
                Function function = functions.next();
                DecompileResults result = opened ? decompiler.decompileFunction(function, 15, monitor) : null;
                boolean success = result != null && result.decompileCompleted() && result.getDecompiledFunction() != null;
                if (!success) failures++;
                String code = success ? result.getDecompiledFunction().getC() : "";
                boolean codeTruncated = code.length() > 262144;
                if (codeTruncated) code = code.substring(0, 262144);
                StringBuilder assembly = new StringBuilder();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                int count = 0;
                while (instructions.hasNext() && count++ < 5000 && assembly.length() < 262144) {
                    Instruction instruction = instructions.next();
                    assembly.append(instruction.getAddress()).append("  ").append(instruction).append('\n');
                }
                boolean assemblyTruncated = instructions.hasNext();
                if (assemblyTruncated || codeTruncated) instructionTruncations++;
                Set<Function> outgoing = function.getCalledFunctions(monitor);
                Set<Function> incoming = function.getCallingFunctions(monitor);
                String line = "{\"kind\":\"function\",\"address\":" + quote(function.getEntryPoint().toString())
                    + ",\"name\":" + quote(function.getName(true)) + ",\"signature\":" + quote(function.getPrototypeString(false, false))
                    + ",\"external\":" + function.isExternal() + ",\"thunk\":" + function.isThunk()
                    + ",\"calls\":" + calls(outgoing) + ",\"called_by\":" + calls(incoming)
                    + ",\"call_edges_truncated\":" + (outgoing.size() > 500 || incoming.size() > 500)
                    + ",\"decompilation_completed\":" + success
                    + ",\"decompilation_error\":" + quote(success ? null : result == null ? "decompiler unavailable" : result.getErrorMessage())
                    + ",\"pseudocode\":" + quote(code) + ",\"pseudocode_truncated\":" + codeTruncated
                    + ",\"assembly\":" + quote(assembly.toString()) + ",\"assembly_truncated\":" + assemblyTruncated + "}";
                if (!record(writer, line)) { byteLimit = true; break; }
                processed++;
                writer.flush();
            }
            // A footer distinguishes a finished export from a killed process.
            writer.write("{\"kind\":\"completion\",\"functions_exported\":" + processed
                + ",\"functions_discovered\":" + currentProgram.getFunctionManager().getFunctionCount()
                + ",\"decompilation_failures\":" + failures + ",\"function_output_truncations\":" + instructionTruncations
                + ",\"byte_limit_reached\":" + byteLimit + ",\"symbol_limit_reached\":" + symbolLimit
                + ",\"cancelled\":" + monitor.isCancelled() + ",\"behavioral_coverage\":\"not_measured\"}");
            writer.newLine();
        } finally { decompiler.dispose(); }
    }
}
