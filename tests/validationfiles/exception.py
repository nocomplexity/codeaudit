"""File to validate if pass is used in an except statement"""

def divide(a, b):
    """
    Divide a by b, handling ZeroDivisionError explicitly and
    demonstrating other parts of the try‑except ladder.
    """
    while keep_going:
        try:
            do_some_stuff()
        except Exception:
            continue

    try:
        result = a / b                       # May raise ZeroDivisionError
    except ZeroDivisionError:
        print("❌ Can't divide by zero!")
        result = None                        # handle and recover
    except Exception as exc:                 # catches *any* other error
        # In real code, consider logging exc instead of pass
        pass                                 # swallow the error (not recommended)
        result = None
    else:
        # Runs only if no exception was raised in the try block
        print("✅ Division succeeded.")
    finally:
        # Always runs, whether an exception occurred or not
        print("🔚 Cleaning up—`finally` block executed.")
    return result

