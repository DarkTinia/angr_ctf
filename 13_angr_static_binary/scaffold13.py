# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc'])
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc
#
# Additionally, note that, when the binary is executed, the main function is not
# the first piece of code called. In the _start function, __libc_start_main is 
# called to start your program. The initialization that occurs in this function
# can take a long time with Angr, so you should replace it with a SimProcedure.
# angr.SIM_PROCEDURES['glibc']['__libc_start_main']
# Note 'glibc' instead of 'libc'.

import angr
import sys
import claripy

def finds(state):
    date = state.posix.dumps(sys.stdout.fileno())
    return "Good Job.".encode() in date
def avoids(state):
    date = state.posix.dumps(sys.stdout.fileno())
    return "Try again.".encode() in date

def main():
    project = angr.Project('13_angr_static_binary')
    env = project.factory.entry_state()
    # project.hook(0x0804A250, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())
    # project.hook(0x08051550, angr.SIM_PROCEDURES['libc']['printf']())
    # project.hook(0x080515A0, angr.SIM_PROCEDURES['libc']['scanf']())
    # project.hook(0x0805F120, angr.SIM_PROCEDURES['libc']['puts']())
    simulation = project.factory.simgr(env, veritesting = True)
    simulation.explore(find = finds, avoid = avoids)
    if(simulation.found):
        solution = simulation.found[0]
        ans = solution.posix.dumps(sys.stdin.fileno()).decode()
        print('solution is {0}'.format(ans))
    else:
        raise Exception('not found')

if __name__ == '__main__':
    main()
    