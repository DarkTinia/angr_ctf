import angr
import claripy
import sys

def main(argv):
  ELFbase = 0x400000
  path_to_binary = '05_angr_symbolic_memory'
  project = angr.Project(path_to_binary)

  start_address = 0x080485FE#ELFbase + 0x134F
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)
  password0 = claripy.BVS('password0', 64)
  password1 = claripy.BVS('password1', 64)
  password2 = claripy.BVS('password2', 64)
  password3 = claripy.BVS('password3', 64)

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)
  password0_address = 0x09FD92A0#ELFbase + 0x0089D540
  password1_address = 0x09FD92A8#ELFbase + 0x0089D548
  password2_address = 0x09FD92B0#ELFbase + 0x0089D550
  password3_address = 0x09FD92B8#ELFbase + 0x0089D558
  initial_state.memory.store(password0_address, password0)
  initial_state.memory.store(password1_address, password1)
  initial_state.memory.store(password2_address, password2)
  initial_state.memory.store(password3_address, password3)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return "Good Job.".encode() in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return "Try again.".encode() in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=str
    # which returns a string instead of an integer.
    # (!)
    solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
    solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()
    solution2 = solution_state.solver.eval(password2,cast_to=bytes).decode()
    solution3 = solution_state.solver.eval(password3,cast_to=bytes).decode()
    solution = solution0 + ' ' +solution1 + ' ' + solution2 + ' ' + solution3
    print(solution)
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
