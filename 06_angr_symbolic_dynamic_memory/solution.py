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
    project = angr.Project('06_angr_symbolic_dynamic_memory')
    
    env = project.factory.blank_state(addr = 0x080493D6)
    env.regs.ebx = 0x0804C000

    pwd0 = claripy.BVS('pwd0',64)
    pwd1 = claripy.BVS('pwd1',64)
    heap0 = 0x5555500
    heap1 = 0x5555510
    addr0 = 0x088E556C
    addr1 = 0x088E5574
    env.memory.store(addr0, heap0, endness = project.arch.memory_endness)
    env.memory.store(addr1, heap1, endness = project.arch.memory_endness)
    env.memory.store(heap0, pwd0)
    env.memory.store(heap1, pwd1)

    simulation = project.factory.simgr(env)
    simulation.explore(find = finds, avoid = avoids)

    if(simulation.found):
        solution = simulation.found[0]
        ans0 = solution.solver.eval(pwd0, cast_to = bytes).decode()
        ans1 = solution.solver.eval(pwd1, cast_to = bytes).decode()
        print(ans0 + ' ' + ans1)
    else:
        raise Exception("not found")


    

if __name__ == '__main__':
    main()
    