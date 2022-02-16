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
    ELFbase = 0x400000
    start_address = ELFbase + 0x00001426
    project = angr.Project('./04_angr_symbolic_stack')
    env = project.factory.blank_state(addr = start_address)
    
    env.regs.ebp = env.regs.esp
    env.regs.esp -= 8
    pwd0 = claripy.BVS("pwd0", 32)
    pwd1 = claripy.BVS("pwd1", 32)
    env.stack_push(pwd1)
    env.stack_push(pwd0)
    env.regs.esp -= 8
    
    simulation = project.factory.simgr(env)
    simulation.explore(find = finds, avoid = avoids)

    if(simulation.found):
        solution = simulation.found[0]
        ans0 = solution.solver.eval(pwd0)
        ans1 = solution.solver.eval(pwd1)
        print(str(hex(ans0)) + ' ' + str(hex(ans1)))
    else:
        raise Exception("not found")


if __name__ == '__main__':
    main()