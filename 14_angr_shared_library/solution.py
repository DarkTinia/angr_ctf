import angr
import sys
import claripy

ELFbase = 0x500000

def main():
    project = angr.Project('lib14_angr_shared_library.so',load_options={
        'main_opts' : {
            'custom_base_addr' : ELFbase
        }
    })
    func_addr = ELFbase+0x129c
    pwd_addr = claripy.BVV(0x300000,32)
    env = project.factory.call_state(func_addr, pwd_addr, claripy.BVV(8,32))
    pwd = claripy.BVS('pwd', 8*8)
    env.memory.store(pwd_addr, pwd)
    
    simulation = project.factory.simgr(env)
    simulation.explore(find = ELFbase+0x134C)
    if(simulation.found):
        solution = simulation.found[0]
        solution.add_constraints(solution.regs.eax != 0)
        ans = solution.solver.eval(pwd, cast_to = bytes).decode()
        print(ans)
    else:
        raise Exception('nout found')
    

if __name__ == '__main__':
    main()
    