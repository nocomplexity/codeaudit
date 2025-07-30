import sys

def my_func(x, y):
    print(f"Adding {x} + {y}")
    return x + y

def trace_func(frame, event, arg):
    print(f"TRACE: {event} at line {frame.f_lineno}")
    return trace_func

def run_with_trace():
    result = sys.call_tracing(my_func, (3, 4))
    print(f"Result: {result}")


def my_func(x, y):
    print(f"Adding {x} + {y}")
    return x + y

def profile_func(frame, event, arg):
    if event in ("call", "return"):
        code = frame.f_code
        func_name = code.co_name
        lineno = frame.f_lineno
        print(f"PROFILE: {event.upper()} in {func_name} at line {lineno}")
    return profile_func

def run_with_profile():
    sys.setprofile(profile_func)
    result = my_func(5, 7)
    sys.setprofile(None)  # Turn off profiling
    print(f"Result: {result}")

def run_with_trace2():
    sys.settrace(trace_func)
    my_func(2, 3)
    sys.settrace(None)  # Disable tracing



def all_sys_shit():
    run_with_profile()
    run_with_trace()
    run_with_trace2()
