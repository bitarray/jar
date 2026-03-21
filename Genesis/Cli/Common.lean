/-
  Genesis CLI — Shared IO Helpers

  All CLI tools follow the same pattern:
  read JSON from stdin → call Genesis functions → write JSON to stdout.
  On error: {"error": "..."} to stderr, exit 1.
-/

import Lean.Data.Json
import Genesis.Json

namespace Genesis.Cli

open Lean (Json toJson fromJson?)

/-- Read all of stdin as a string. -/
def readStdin : IO String := do
  let stdin ← IO.getStdin
  let mut buf := ""
  repeat do
    let line ← stdin.getLine
    if line.isEmpty then break
    buf := buf ++ line
  return buf

/-- Parse JSON from stdin, run a function, print result JSON to stdout.
    On error, print JSON {"error": "..."} to stderr and exit 1. -/
def runJsonPipe (f : Json → IO Json) : IO UInt32 := do
  try
    let input ← readStdin
    let json ← IO.ofExcept (Json.parse input)
    let result ← f json
    IO.println result.compress
    return 0
  catch e =>
    let errJson := Json.mkObj [("error", Json.str (toString e))]
    (← IO.getStderr).putStrLn errJson.compress
    return 1

end Genesis.Cli
