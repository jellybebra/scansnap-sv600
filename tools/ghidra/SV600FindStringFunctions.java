// Find and decompile functions that reference ScanSnap SV600 diagnostic strings.
// @category ScanSnap

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.DefinedDataIterator;

public class SV600FindStringFunctions extends GhidraScript {
    private static final String[] DEFAULT_NEEDLES = {
        "Conv_Scan",
        "WaitResponseAndOnCameraCmd",
        "SendAndOnCameraCmd",
        "ChkAndOnCameraAlive",
        "RunCameraAPP",
        "InitCameraAPP",
        "Comet_BeginScan",
        "BeginScanningThread",
        "Make_CdbCommand",
        "OpenUSBDevice",
        "WAIT STILL SCAN",
        "SET SCAN MODE",
        "SET SCAN",
        "END WAITING SCAN",
        "PFU_BoePo_Camera"
    };

    @Override
    protected void run() throws Exception {
        String[] needles = getScriptArgs();
        if (needles.length == 0) {
            needles = DEFAULT_NEEDLES;
        }

        Map<Function, Set<String>> matches = new LinkedHashMap<>();
        AddressSetView memory = currentProgram.getMemory();
        for (Data data : DefinedDataIterator.definedStrings(currentProgram, memory)) {
            String rendered = data.getDefaultValueRepresentation();
            for (String needle : needles) {
                if (!rendered.contains(needle)) {
                    continue;
                }
                println("STRING " + data.getAddress() + " " + rendered);
                boolean foundReference = false;
                for (int offset = 0; offset < data.getLength(); offset++) {
                    Address address = data.getAddress().add(offset);
                    ReferenceIterator references =
                        currentProgram.getReferenceManager().getReferencesTo(address);
                    while (references.hasNext()) {
                        Reference reference = references.next();
                        Function function = currentProgram.getFunctionManager()
                            .getFunctionContaining(reference.getFromAddress());
                        if (function == null) {
                            continue;
                        }
                        foundReference = true;
                        matches.computeIfAbsent(function, ignored -> new LinkedHashSet<>())
                            .add(needle + " @ " + reference.getFromAddress());
                    }
                }
                if (!foundReference) {
                    println("  (no direct code reference found)");
                }
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) {
            printerr("Unable to initialize decompiler");
            return;
        }

        for (Map.Entry<Function, Set<String>> entry : matches.entrySet()) {
            Function function = entry.getKey();
            println("\n/* MATCHES " + String.join(", ", entry.getValue()) + " */");
            println("/* " + function.getName() + " @ " + function.getEntryPoint() + " */");
            DecompileResults results = decompiler.decompileFunction(function, 180, monitor);
            if (!results.decompileCompleted()) {
                printerr("Failed to decompile " + function.getName() + ": " +
                    results.getErrorMessage());
                continue;
            }
            println(results.getDecompiledFunction().getC());
        }
        decompiler.dispose();
    }
}
