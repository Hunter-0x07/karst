"""Three research-frontier resets with real HTTP; --mock is development only."""

from run_i0_batch import main

if __name__ == "__main__":
    raise SystemExit(main(stage="research"))
