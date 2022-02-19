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
    project = angr.Project('10_angr_simprocedures')
    env = project.factory.entry_state()
    class fuck_cmp(angr.SimProcedure):
        def run(self, str_addr, len):
            inputs_str = self.state.memory.load(str_addr, len)
            target_str = "DOJEZIWFDDJJVPJW"
            return claripy.If(
                inputs_str == target_str,
                claripy.BVV(1,32),
                claripy.BVV(0,32)
            )
    func_name = 'check_equals_DOJEZIWFDDJJVPJW'
    project.hook_symbol(func_name, fuck_cmp())
    
    simulation = project.factory.simgr(env)
    simulation.explore(find = finds, avoid = avoids)
    if(simulation.found):
        solution = simulation.found[0]
        ans = solution.posix.dumps(sys.stdin.fileno()).decode()
        print(ans)
    else:
        raise Exception('not found')

if __name__ == '__main__':
    main()
    