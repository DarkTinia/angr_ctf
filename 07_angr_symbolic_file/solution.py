import angr
import sys
import claripy

ELFbase = 0x400000

def finds(state):
    date = state.posix.dumps(sys.stdout.fileno())
    return "Good Job.".encode() in date
def avoids(state):
    date = state.posix.dumps(sys.stdout.fileno())
    return "Try again.".encode() in date

def main():
    project = angr.Project('07_angr_symbolic_file')
    env = project.factory.blank_state(addr = ELFbase+0x15DA)
    env.regs.ebx = ELFbase+0x3FA8

    filename = 'DOJEZIWF.txt'
    file_size = 0x40
    pwd = claripy.BVS('pwd', file_size*8)
    file = angr.storage.SimFile(filename, pwd, file_size)
    env.fs.insert(filename, file)
    simulation = project.factory.simgr(env)
    simulation.explore(find = finds, avoid = avoids)
    if(simulation.found):
        solution = simulation.found[0]
        ans = solution.solver.eval(pwd, cast_to = bytes).decode()
        print(ans)

if __name__ == '__main__':
    main()
    