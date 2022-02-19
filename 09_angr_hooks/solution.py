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
    project = angr.Project('09_angr_hooks')
    env = project.factory.entry_state()
    hook_addr = ELFbase + 0x1452
    hook_len = 5 
    @project.hook(hook_addr, length = hook_len)
    def hook_func(state):
        target = "DOJEZIWFDDJJVPJW"
        inputs_addr = ELFbase + 0x402C
        inputs = state.memory.load(inputs_addr, 0x10)
        state.regs.eax = claripy.If(
            target == inputs,
            claripy.BVV(1,32),
            claripy.BVV(0,32)
        )
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
    