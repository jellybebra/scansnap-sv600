# Decompile functions whose instructions contain supplied scalar constants.
# @category ScanSnap

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.scalar import Scalar


targets = {}
for argument in getScriptArgs():
    value = int(argument, 0)
    targets[value] = argument

matches = {}
instructions = currentProgram.getListing().getInstructions(True)
while instructions.hasNext():
    instruction = instructions.next()
    for operand_index in range(instruction.getNumOperands()):
        for obj in instruction.getOpObjects(operand_index):
            if not isinstance(obj, Scalar):
                continue
            unsigned = obj.getUnsignedValue()
            if unsigned not in targets:
                continue
            function = currentProgram.getFunctionManager().getFunctionContaining(
                instruction.getAddress()
            )
            if function is None:
                continue
            entry = str(function.getEntryPoint())
            record = matches.setdefault(entry, {"function": function, "refs": []})
            reason = "{} @ {}".format(targets[unsigned], instruction.getAddress())
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
        println("\n/* SCALARS {} */".format(", ".join(record["refs"])))
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
