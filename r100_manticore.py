# longer than angr but slightly faster
from manticore.native import Manticore

m = Manticore("examples/r100", auto_load=False)
m.verbosity(0)

@m.hook(0x400844)
def print_flag(state):
    with m.locked_context() as context:
        con_buf = state.solve_buffer(context["buf_addr"], 0xc)
        con_buf = "".join(chr(c) for c in con_buf)
        print("FLAG SHOULD BE:", con_buf)
        m.terminate()

@m.hook(0x400838)
def symbolicate_password(state):
    buf = state.new_symbolic_buffer(0xff) # buffer we will solve
    with m.locked_context() as context:
        context["buf_addr"] = state.cpu.RAX

    state.cpu.write_bytes(state.cpu.RAX, buf)

##### skip some libc stuff #####
@m.hook(0x400634)
def skip_things(state):
    state.cpu.RIP = 0x4007e8

@m.hook(0x4007f3)
def skip_more_things(state):
    state.cpu.RIP = 0x400831

m.run(procs=8)
