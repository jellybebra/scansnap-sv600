# Decompile functions containing addresses supplied on the command line.
# @category ScanSnap

from ghidra.app.decompiler import DecompInterface


decompiler = DecompInterface()
decompiler.toggleCCode(True)
decompiler.toggleSyntaxTree(True)

if not decompiler.openProgram(currentProgram):
    printerr("Unable to initialize decompiler")
else:
    seen = set()
    for argument in getScriptArgs():
        address = currentProgram.getAddressFactory().getAddress(argument)
        if address is None:
            printerr("Invalid address: {}".format(argument))
            continue
        function = currentProgram.getFunctionManager().getFunctionContaining(address)
        if function is None:
            printerr("No function contains {}".format(argument))
            continue
        entry = str(function.getEntryPoint())
        if entry in seen:
            continue
        seen.add(entry)
        println("\n/* {} @ {} */".format(function.getName(), entry))
        results = decompiler.decompileFunction(function, 180, monitor)
        if not results.decompileCompleted():
            printerr(
                "Failed to decompile {}: {}".format(
                    function.getName(), results.getErrorMessage()
                )
            )
            continue
        println(str(results.getDecompiledFunction().getC()))
    decompiler.dispose()
