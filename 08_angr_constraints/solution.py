import angr
import sys
import claripy

ELFbase = 0x400000

def main():
    project = angr.Project('./08_angr_constraints')
    env = project.factory.blank_state(addr = ELFbase+0x13D9)
    env.regs.ebx = ELFbase+0x3FC8
    pwd = claripy.BVS('pwd', 0x10*8)
    pwd_addr = ELFbase + 0x402C
    env.memory.store(pwd_addr, pwd)
    simulation = project.factory.simgr(env)
    simulation.explore(find = ELFbase + 0x1431)
    if(simulation.found):
        solution = simulation.found[0]
        current_str = env.memory.load(pwd_addr, 0x10)
        target_str = "DOJEZIWFDDJJVPJW"
        solution.add_constraints(current_str == target_str)
        ans = solution.solver.eval(pwd, cast_to = bytes).decode()
        print(ans)
    else:
        raise Exception('not found')

if __name__ == '__main__':
    main()
    