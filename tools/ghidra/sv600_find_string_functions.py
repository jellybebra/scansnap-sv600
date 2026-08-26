# Find and decompile functions that reference ScanSnap SV600 diagnostic strings.
# @category ScanSnap

from ghidra.app.decompiler import DecompInterface
DEFAULT_NEEDLES = (
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
    "PFU_BoePo_Camera",
)


needles = tuple(getScriptArgs()) or DEFAULT_NEEDLES
matches = {}

defined_data = currentProgram.getListing().getDefinedData(True)
while defined_data.hasNext():
    data = defined_data.next()
    rendered = str(data.getDefaultValueRepresentation())
    for needle in needles:
        if needle not in rendered:
            continue
        println("STRING {} {}".format(data.getAddress(), rendered))
        found_reference = False
        for offset in range(data.getLength()):
            address = data.getAddress().add(offset)
            references = currentProgram.getReferenceManager().getReferencesTo(address)
            while references.hasNext():
                reference = references.next()
                function = currentProgram.getFunctionManager().getFunctionContaining(
                    reference.getFromAddress()
                )
                if function is None:
                    continue
                found_reference = True
                entry = str(function.getEntryPoint())
                record = matches.setdefault(entry, {"function": function, "reasons": []})
                reason = "{} @ {}".format(needle, reference.getFromAddress())
                if reason not in record["reasons"]:
                    record["reasons"].append(reason)
        if not found_reference:
            println("  (no direct code reference found)")

decompiler = DecompInterface()
decompiler.toggleCCode(True)
decompiler.toggleSyntaxTree(True)
if not decompiler.openProgram(currentProgram):
    printerr("Unable to initialize decompiler")
else:
    for entry in sorted(matches):
        record = matches[entry]
        function = record["function"]
        println("\n/* MATCHES {} */".format(", ".join(record["reasons"])))
        println("/* {} @ {} */".format(function.getName(), function.getEntryPoint()))
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
