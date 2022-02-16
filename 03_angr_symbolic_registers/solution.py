import angr
import sys
import claripy

def finds(state):
    date = state.posix.dumps(sys.stdout.fileno())
    return 'Good Job.'.encode() in date

def avoids(state):
    date = state.posix.dumps(sys.stdout.fileno())
    return 'Try again.'.encode() in date


def main():
    project = angr.Project('03_angr_symbolic_registers')
    start_address = 0x804890E
    env = project.factory.blank_state(addr = start_address)

    pwd_len = 32
    pwd0 = claripy.BVS("pwd0", pwd_len)
    pwd1 = claripy.BVS("pwd1", pwd_len)
    pwd2 = claripy.BVS("pwd2", pwd_len)

    env.regs.eax = pwd0
    env.regs.ebx = pwd1
    env.regs.edx = pwd2

    simulation = project.factory.simgr(env)
    simulation.explore(find = finds, avoid = avoids)

    if(simulation.found):
        solution = simulation.found[0]
        ax = solution.solver.eval(pwd0)
        bx = solution.solver.eval(pwd1)
        dx = solution.solver.eval(pwd2)
        print(str(hex(ax))+' '+str(hex(bx))+' '+str(hex(dx)))
    else:
        raise Exception("not found")

if __name__ == '__main__':
    main()