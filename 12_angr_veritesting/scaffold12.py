# When you construct a simulation manager, you will want to enable Veritesting:
# project.factory.simgr(initial_state, veritesting=True)
# Hint: use one of the first few levels' solutions as a reference.

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
    project = angr.Project('12_angr_veritesting.c.templite')
    env = project.factory.entry_state()
    simulation = project.factory.simgr(env, veritesting = True)
    simulation.explore(find = finds, avoid = avoids)
    if(simulation.found):
        solution = simulation.found[0]
        ans = solution.posix.dumps(sys.stdin.fileno()).decode()
        print(ans)
    else:
        raise Exception('not found')

if __name__ == '__main__':
    main()
    