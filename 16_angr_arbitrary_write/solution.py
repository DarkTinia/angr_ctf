import angr
import sys
import claripy

ELFbase = 0x400000

def main():
    project = angr.Project('16_angr_arbitrary_write')
    env = project.factory.entry_state()
    
    class fuck_scnaf(angr.SimProcedure):
        def run(self, format, addr0, addr1):
            scanf0 = claripy.BVS('scnaf0', 32)
            scanf1 = claripy.BVS('scanf1', 20*8)
            self.state.memory.store(addr0, scanf0, endness = project.arch.memory_endness)
            self.state.memory.store(addr1, scanf1)
            self.state.globals['solution'] = (scanf0, scanf1)
    scnaf_symbol = '__isoc99_scanf'
    project.hook_symbol(scnaf_symbol, fuck_scnaf())
    
    def check_strncpy(state):
        strncpy_dest = state.memory.load(state.regs.esp+4, 4, endness = project.arch.memory_endness)
        strncpy_src = state.memory.load(state.regs.esp+8, 4, endness = project.arch.memory_endness)
        strncpy_len = state.memory.load(state.regs.esp+12, 4, endness = project.arch.memory_endness)
        src_strs = state.memory.load(strncpy_src, strncpy_len)
        if(state.solver.symbolic(strncpy_dest) and state.solver.symbolic(src_strs)):
            target_str = 'ZIWFDDJJ'
            check1 = src_strs[-1:-64] == target_str
            check2 = strncpy_dest == ELFbase+0x444F4A48
            if(state.satisfiable(extra_constraints=(check1, check2))):
                state.add_constraints(check1, check2)
                return True
            else:
                return False
        else:
            return False
    
    def finds(state):
        if(state.addr == ELFbase+0x1100):
            return check_strncpy(state)
        else:
            return False
    simulation = project.factory.simgr(env)
    simulation.explore(find = finds)
    if(simulation.found):
        solution = simulation.found[0]
        (scnaf0, scanf1) = solution.globals['solution']
        ans0 = solution.solver.eval(scnaf0)
        ans1 = solution.solver.eval(scanf1, cast_to = bytes)
        solution = 'solution is {0} {1}'.format(ans0, ans1)
        print(solution)
    else:
        raise Exception('not found')
    


if __name__ == '__main__':
    main()
    