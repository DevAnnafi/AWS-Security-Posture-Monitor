"""Check discovery and registration.

TODO: decide how checks announce themselves - decorator-based registry vs.
      module scanning. This decision determines how cheap check #7 through
      #40 are to add, and how shared API calls get cached across checks.
"""