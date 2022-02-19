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
    project = angr.Project('11_angr_sim_scanf')
    env = project.factory.entry_state()
    class fuck_scanf(angr.SimProcedure):
        def run(self, format, addr0, addr1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 32)
            self.state.memory.store(addr0, scanf0, endness = project.arch.memory_endness)
            self.state.memory.store(addr1, scanf1, endness = project.arch.memory_endness)
            self.state.globals['scanf_para'] = (scanf0, scanf1)
            return
    func_name = '__isoc99_scanf'
    project.hook_symbol(func_name, fuck_scanf())
    simulation = project.factory.simgr(env)
    simulation.explore(find = finds, avoid = avoids)

    if(simulation.found):
        solution = simulation.found[0]
        scanf_para = simulation.globals['scanf_para']
        ans0 = solution.solver.eval(scanf_para[0])
        ans1 = solution.solver.eval(scanf_para[1])
        print('Solution is {0} {1}', ans0, ans1)
    else:
        raise Exception('not found')


if __name__ == '__main__':
    main()
    
