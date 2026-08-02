// Exports one JSON object per discovered function, including exact body ranges and byte identities.
//@category DolphinRedux

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ExportFunctionCatalog extends GhidraScript {
  private static String json(String value) {
    StringBuilder result = new StringBuilder("\"");
    for (int i = 0; i < value.length(); ++i) {
      char c = value.charAt(i);
      switch (c) {
        case '\\': result.append("\\\\"); break;
        case '"': result.append("\\\""); break;
        case '\n': result.append("\\n"); break;
        case '\r': result.append("\\r"); break;
        case '\t': result.append("\\t"); break;
        default:
          if (c < 0x20) result.append(String.format("\\u%04x", (int)c));
          else result.append(c);
      }
    }
    return result.append('"').toString();
  }

  private static String addresses(Set<Function> functions) {
    List<String> values = new ArrayList<>();
    for (Function function : functions)
      values.add(function.getEntryPoint().toString());
    Collections.sort(values);
    for (int i = 0; i < values.size(); ++i)
      values.set(i, json(values.get(i)));
    return "[" + String.join(",", values) + "]";
  }

  private static String hex(byte[] bytes) {
    StringBuilder result = new StringBuilder(bytes.length * 2);
    for (byte value : bytes)
      result.append(String.format("%02x", value & 0xff));
    return result.toString();
  }

  private static String sha256(byte[] bytes) throws Exception {
    return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }

  private String bodyRanges(Function function) throws Exception {
    List<String> values = new ArrayList<>();
    AddressRangeIterator ranges = function.getBody().getAddressRanges(true);
    while (ranges.hasNext()) {
      AddressRange range = ranges.next();
      long length = range.getLength();
      if (length > Integer.MAX_VALUE)
        throw new IllegalStateException("function body range is too large to export");
      byte[] bytes = new byte[(int)length];
      int read = currentProgram.getMemory().getBytes(range.getMinAddress(), bytes);
      if (read != bytes.length)
        throw new IllegalStateException("could not read complete function body range at " +
                                        range.getMinAddress());
      values.add("{\"start\":" + json(range.getMinAddress().toString()) +
                 ",\"end\":" + json(range.getMaxAddress().toString()) +
                 ",\"bytes\":" + json(hex(bytes)) +
                 ",\"sha256\":" + json(sha256(bytes)) + "}");
    }
    return "[" + String.join(",", values) + "]";
  }

  private Set<String> referencedStrings(Function function) {
    Set<String> values = new LinkedHashSet<>();
    AddressIterator addresses = function.getBody().getAddresses(true);
    while (addresses.hasNext() && values.size() < 12) {
      Reference[] references = currentProgram.getReferenceManager().getReferencesFrom(addresses.next());
      for (Reference reference : references) {
        if (values.size() >= 12) break;
        Data data = currentProgram.getListing().getDataContaining(reference.getToAddress());
        if (data == null) continue;
        Object value = data.getValue();
        if (value instanceof String && !((String)value).isEmpty())
          values.add((String)value);
      }
    }
    return values;
  }

  private static String strings(Set<String> strings) {
    List<String> values = new ArrayList<>(strings);
    Collections.sort(values);
    for (int i = 0; i < values.size(); ++i)
      values.set(i, json(values.get(i)));
    return "[" + String.join(",", values) + "]";
  }

  private static Long parseBound(String text) {
    String normalized = text.replaceFirst("^0[xX]", "");
    return Long.parseUnsignedLong(normalized, 16);
  }

  @Override public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length < 1 || args.length > 3)
      throw new IllegalArgumentException(
          "usage: ExportFunctionCatalog.java <output.jsonl> [minimum-address] " +
          "[maximum-address-exclusive]");
    Long minimum = args.length >= 2 ? parseBound(args[1]) : null;
    Long maximum = args.length >= 3 ? parseBound(args[2]) : null;
    int count = 0;
    try (BufferedWriter output = new BufferedWriter(new FileWriter(args[0]))) {
      FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
      while (functions.hasNext()) {
        monitor.checkCancelled();
        Function function = functions.next();
        Address address = function.getEntryPoint();
        long offset = address.getOffset();
        if ((minimum != null && Long.compareUnsigned(offset, minimum) < 0) ||
            (maximum != null && Long.compareUnsigned(offset, maximum) >= 0))
          continue;
        Set<Function> callers = function.getCallingFunctions(monitor);
        Set<Function> callees = function.getCalledFunctions(monitor);
        Set<String> referencedStrings = referencedStrings(function);
        output.write("{\"address\":" + json(address.toString()) +
                     ",\"ghidra_name\":" + json(function.getName()) +
                     ",\"size\":" + function.getBody().getNumAddresses() +
                     ",\"body_ranges\":" + bodyRanges(function) +
                     ",\"is_thunk\":" + function.isThunk() +
                     ",\"caller_count\":" + callers.size() +
                     ",\"callers\":" + addresses(callers) +
                     ",\"callee_count\":" + callees.size() +
                     ",\"callees\":" + addresses(callees) +
                     ",\"strings\":" + strings(referencedStrings) + "}");
        output.newLine();
        ++count;
      }
    }
    println("Exported " + count + " functions to " + args[0]);
  }
}
