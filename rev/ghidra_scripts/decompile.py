# Decompile all functions to output.c
# @author nneonneo
# @category PWN
# @keybinding
# @menupath
# @toolbar

from ghidra.app.decompiler import DecompInterface, DecompileOptions

curr = getCurrentProgram()
decompiler = DecompInterface()
opts = DecompileOptions()
opts.grabFromProgram(curr)
decompiler.setOptions(opts)
decompiler.toggleCCode(True)
decompiler.toggleSyntaxTree(True)
decompiler.setSimplificationStyle("decompile")
decompiler.openProgram(curr)

with open("output.c", "w") as outf:
    funcs = curr.functionManager.getFunctions(True)
    for func in funcs:
        res = decompiler.decompileFunction(func, 0, monitor)
        if res.decompiledFunction is None:
            d = "/* Error decompiling %s: %s */" % (func.getName(True), res.errorMessage)
        else:
            d = res.decompiledFunction.c

        print >>outf, d
