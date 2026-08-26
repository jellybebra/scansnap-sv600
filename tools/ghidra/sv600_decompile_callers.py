# Decompile every function that directly references the supplied function addresses.
# @category ScanSnap

from ghidra.app.decompiler import DecompInterface


function_manager = currentProgram.getFunctionManager()
reference_manager = currentProgram.getReferenceManager()
callers = {}

for argument in getScriptArgs():
    address = currentProgram.getAddressFactory().getAddress(argument)
    if address is None:
        printerr("Invalid address: {}".format(argument))
        continue
    callee = function_manager.getFunctionAt(address)
    if callee is None:
        printerr("No function starts at {}".format(argument))
        continue
    references = reference_manager.getReferencesTo(callee.getEntryPoint())
    while references.hasNext():
        reference = references.next()
        caller = function_manager.getFunctionContaining(reference.getFromAddress())
        if caller is None:
            continue
        entry = str(caller.getEntryPoint())
        record = callers.setdefault(entry, {"function": caller, "calls": []})
        reason = "{} from {}".format(argument, reference.getFromAddress())
        if reason not in record["calls"]:
            record["calls"].append(reason)

decompiler = DecompInterface()
decompiler.toggleCCode(True)
decompiler.toggleSyntaxTree(True)
if not decompiler.openProgram(currentProgram):
    printerr("Unable to initialize decompiler")
else:
    for entry in sorted(callers):
        record = callers[entry]
        function = record["function"]
        println("\n/* CALLS {} */".format(", ".join(record["calls"])))
        println("/* {} @ {} */".format(function.getName(), entry))
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
