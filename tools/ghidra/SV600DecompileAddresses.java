// Decompile functions containing addresses supplied on the command line.
// @category ScanSnap

import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class SV600DecompileAddresses extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        if (!decompiler.openProgram(currentProgram)) {
            printerr("Unable to initialize decompiler");
            return;
        }

        Set<Address> seen = new LinkedHashSet<>();
        for (String argument : getScriptArgs()) {
            Address address = currentProgram.getAddressFactory().getAddress(argument);
            if (address == null) {
                printerr("Invalid address: " + argument);
                continue;
            }
            Function function = currentProgram.getFunctionManager()
                .getFunctionContaining(address);
            if (function == null) {
                printerr("No function contains " + argument);
                continue;
            }
            if (!seen.add(function.getEntryPoint())) {
                continue;
            }

            println("\n/* " + function.getName() + " @ " +
                function.getEntryPoint() + " */");
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
