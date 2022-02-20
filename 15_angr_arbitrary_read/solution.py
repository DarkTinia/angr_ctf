import angr
import sys
import claripy

ELFbase = 0x400000

def main():
    project = angr.Project('15_angr_arbitrary_read')
    env = project.factory.entry_state()
    
    class fuck_scanf(angr.SimProcedure):
        def run(self, format, addr0, addr1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 20*8)
            self.state.memory.store(addr0, scanf0, endness = project.arch.memory_endness)
            self.state.memory.store(addr1, scanf1)
            self.state.globals['solution'] = (scanf0, scanf1)
    scanf_str = '__isoc99_scanf'
    project.hook_symbol(scanf_str, fuck_scanf())

    def check_good(state):
        puts_str = state.memory.load(state.regs.esp+4, 4, endness = project.arch.memory_endness)
        target_str_addr = ELFbase + 0x444F4A47

        if(state.solver.symbolic(puts_str)):
            copy_state = state.copy()
            copy_state.add_constraints(puts_str == target_str_addr)
            if(copy_state.satisfiable()):
                state.add_constraints(puts_str == target_str_addr)
                return True
            else:
                return False
  
        else:
            return False

    def finds(state):
        if state.addr == ELFbase+0x10A0:
            return check_good(state)
        else:
            return False
    simulation = project.factory.simgr(env)
    simulation.explore(find = finds)
    if(simulation.found):
        solution = simulation.found[0]
        (scanf0, scanf1) = solution.globals['solution']
        ans0 = solution.solver.eval(scanf0)
        ans1 = solution.solver.eval(scanf1, cast_to = bytes)
        print("solution is {0} {1}".format(ans0, ans1))
    else:
        raise Exception('not found')

if __name__ == '__main__':
    main()
    