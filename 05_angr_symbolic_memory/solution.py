import angr
import sys
import claripy

def finds(state):
    date = state.posix.dumps(sys.stdout.fileno())
    return "Good Job.".encode() in date
def avoids(state):
    date = state.posix.dumps(sys.stdout.fileno())
    return "Try again.".encode() in date

def main():
    project = angr.Project('05_angr_symbolic_memory')
    env = project.factory.blank_state(addr = 0x080485FE)
    
    pwd0 = claripy.BVS("pwd0", 64)
    pwd1 = claripy.BVS("pwd1", 64)
    pwd2 = claripy.BVS("pwd2", 64)
    pwd3 = claripy.BVS("pwd3", 64)
    env.memory.store(0x09FD92A0, pwd0)
    env.memory.store(0x09FD92A8, pwd1)
    env.memory.store(0x09FD92B0, pwd2)
    env.memory.store(0x09FD92B8, pwd3)

    simulation = project.factory.simgr(env)
    simulation.explore(find = finds, avoid = avoids)

    if(simulation.found):
        solution = simulation.found[0]
        ans0 = solution.solver.eval(pwd0, cast_to=bytes).decode()
        ans1 = solution.solver.eval(pwd1, cast_to=bytes).decode()
        ans2 = solution.solver.eval(pwd2, cast_to=bytes).decode()
        ans3 = solution.solver.eval(pwd3, cast_to=bytes).decode()
        print(ans0 + ' ' + ans1 + ' ' + ans2 + ' ' + ans3)
    else:
        raise Exception("not found")

if __name__ == "__main__":
    main()