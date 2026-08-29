# Decompile functions that directly reference named functions or symbols.
# @category ScanSnap

from ghidra.app.decompiler import DecompInterface


needles = tuple(getScriptArgs())
if not needles:
    printerr("Provide one or more exact or partial symbol names")
    exit()

function_manager = currentProgram.getFunctionManager()
reference_manager = currentProgram.getReferenceManager()
symbol_table = currentProgram.getSymbolTable()
targets = {}

functions = function_manager.getFunctions(True)
while functions.hasNext():
    function = functions.next()
    name = function.getName()
    if any(needle in name for needle in needles):
        targets[str(function.getEntryPoint())] = {
            "name": name,
            "address": function.getEntryPoint(),
        }

symbols = symbol_table.getAllSymbols(True)
while symbols.hasNext():
    symbol = symbols.next()
    name = symbol.getName()
    if any(needle in name for needle in needles):
        targets.setdefault(
            str(symbol.getAddress()),
            {"name": name, "address": symbol.getAddress()},
        )

callers = {}
for target in targets.values():
    println("TARGET {} @ {}".format(target["name"], target["address"]))
    target_function = function_manager.getFunctionAt(target["address"])
    if target_function is not None:
        entry = str(target_function.getEntryPoint())
        record = callers.setdefault(
            entry, {"function": target_function, "reasons": []}
        )
        reason = "TARGET {}".format(target["name"])
        if reason not in record["reasons"]:
            record["reasons"].append(reason)
    references = reference_manager.getReferencesTo(target["address"])
    while references.hasNext():
        reference = references.next()
        caller = function_manager.getFunctionContaining(reference.getFromAddress())
        if caller is None:
            continue
        entry = str(caller.getEntryPoint())
        record = callers.setdefault(entry, {"function": caller, "reasons": []})
        reason = "{} @ {}".format(target["name"], reference.getFromAddress())
        if reason not in record["reasons"]:
            record["reasons"].append(reason)

decompiler = DecompInterface()
decompiler.toggleCCode(True)
decompiler.toggleSyntaxTree(True)
if not decompiler.openProgram(currentProgram):
    printerr("Unable to initialize decompiler")
else:
    for entry in sorted(callers):
        record = callers[entry]
        function = record["function"]
        println("\n/* REFERENCES {} */".format(", ".join(record["reasons"])))
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
