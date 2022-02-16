import angr
import sys

ELFbase = 0x400000

def main():
    project = angr.Project("./01_angr_avoid")
    env = project.factory.entry_state()
    simulation = project.factory.simgr(env)
    target = ELFbase + 0x1374
    bad = ELFbase + 0x1317
    simulation.explore(find = target, avoid = bad)

    if(simulation.found):
        solution = simulation.found[0]
        print(solution.posix.dumps(sys.stdin.fileno()).decode())

if __name__ == '__main__':
    main()