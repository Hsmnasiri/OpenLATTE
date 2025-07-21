import json, sys,os
from ghidra.app.decompiler import DecompInterface
out_edges = []
program = currentProgram()
fm = program.functionManager
for f in fm.getFunctions(True):
    callers = [c.getCallingFunction() for c in f.getCallingFunctions(monitor)]
    for caller in callers:
        out_edges.append([str(caller.getEntryPoint()), str(f.getEntryPoint())])

with open(sys.argv[1],"w") as fp:
    json.dump(out_edges, fp)

INF = DecompInterface(); INF.openProgram(program)

DECOMP_DIR = getProjectHome().toString()+"/decomp"
os.makedirs(DECOMP_DIR, exist_ok=True)
for f in fm.getFunctions(True):
    res = INF.decompileFunction(f, 30, monitor)
    if res.decompileCompleted():
        with open(f"{DECOMP_DIR}/{f.getName()}.c","w") as fp:
            fp.write(res.getDecompiledFunction().getC())