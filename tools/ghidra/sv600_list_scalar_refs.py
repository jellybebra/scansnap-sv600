# List instructions and containing functions that reference scalar constants.
# @category ScanSnap

from ghidra.program.model.scalar import Scalar


targets = {int(argument, 0): argument for argument in getScriptArgs()}
instructions = currentProgram.getListing().getInstructions(True)

while instructions.hasNext():
    instruction = instructions.next()
    for operand_index in range(instruction.getNumOperands()):
        for obj in instruction.getOpObjects(operand_index):
            if not isinstance(obj, Scalar):
                continue
            value = obj.getUnsignedValue()
            if value not in targets:
                continue
            function = currentProgram.getFunctionManager().getFunctionContaining(
                instruction.getAddress()
            )
            function_name = function.getName() if function is not None else "<none>"
            function_entry = (
                str(function.getEntryPoint()) if function is not None else "<none>"
            )
            println(
                "{} instruction={} function={}@{} text={}".format(
                    targets[value],
                    instruction.getAddress(),
                    function_name,
                    function_entry,
                    instruction,
                )
            )
