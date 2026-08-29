# Decompile every function that directly references supplied data addresses.
# @category ScanSnap

from ghidra.app.decompiler import DecompInterface


function_manager = currentProgram.getFunctionManager()
reference_manager = currentProgram.getReferenceManager()
matches = {}

for argument in getScriptArgs():
    address = currentProgram.getAddressFactory().getAddress(argument)
    if address is None:
        printerr("Invalid address: {}".format(argument))
        continue
    references = reference_manager.getReferencesTo(address)
    while references.hasNext():
        reference = references.next()
        function = function_manager.getFunctionContaining(reference.getFromAddress())
        if function is None:
            continue
        entry = str(function.getEntryPoint())
        record = matches.setdefault(entry, {"function": function, "refs": []})
        reason = "{} from {}".format(argument, reference.getFromAddress())
        if reason not in record["refs"]:
            record["refs"].append(reason)

decompiler = DecompInterface()
decompiler.toggleCCode(True)
decompiler.toggleSyntaxTree(True)
if not decompiler.openProgram(currentProgram):
    printerr("Unable to initialize decompiler")
else:
    for entry in sorted(matches):
        record = matches[entry]
        function = record["function"]
        println("\n/* REFERENCES {} */".format(", ".join(record["refs"])))
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
