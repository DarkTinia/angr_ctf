import angr
import sys

def finds(state):
    date = state.posix.dumps(sys.stdin.fileno())
    return 'Good Job.'.encode() in date
def avoids(state):
    date = state.posix.dumps(sys.stdin.fileno())
    return 'Try again.'.encode() in date

def main():
    project = angr.Project('./02_angr_find_condition')
    env = project.factory.entry_state()
    simulation = project.factory.simgr(env)
    simulation.explore(find = finds, avoid = avoids)
    
    if(simulation.found):
        solution = simulation.found[0]
        print(solution.posix.dumps(sys.stdin.fileno()).decode())
if __name__ == '__main__':
    main()