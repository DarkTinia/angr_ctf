import angr
import sys


def main():
    ELFbase = 0x400000   
    ELFpath = './00_angr_find'

    project = angr.Project(ELFpath)
    env = project.factory.entry_state()
    simulation = project.factory.simgr(env)
    simulation.explore(find = ELFbase + 0x13e6)

    if(simulation.found):
        solution = simulation.found[0]
        print(solution.posix.dumps(sys.stdin.fileno()).decode())


if __name__ == '__main__':
    main()