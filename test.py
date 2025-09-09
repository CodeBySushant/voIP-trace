import time
import core

# This is a dummy function required by the sniffer's cleanup thread.
def dummy_cleanup():
    pass

def run_test():
    print("--- Starting Core Engine Test ---")
    print("This will run the sniffer for 15 seconds and then exit.")
    print("Please generate some network traffic now (e.g., start a short call).")

    # Start the sniffer from the core engine
    core.start_sniffer(iface=None, cleanup_callback=dummy_cleanup)

    # Let it run for 15 seconds
    time.sleep(15)

    print("--- Test Finished ---")
    print("Please check the 'voip_trace.log' and 'call_data.jsonl' files now.")

if __name__ == "__main__":
    run_test()

    
