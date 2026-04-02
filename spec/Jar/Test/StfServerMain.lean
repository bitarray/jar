import Jar.Test.StfServer
import Jar.Variant

open Jar

def main (args : List String) : IO UInt32 := do
  match args with
  | "--variant" :: v :: rest =>
    let config ← match v with
      | "gp072_tiny" => pure JamVariant.gp072_tiny.toJamConfig
      | "gp072_full" => pure JamVariant.gp072_full.toJamConfig
      | "jar1" => pure JamVariant.jar1.toJamConfig
      | _ =>
        IO.eprintln s!"Unknown variant: {v}"
        IO.eprintln "Available: gp072_tiny, gp072_full, jar1"
        return 1
    letI := config
    Jar.Test.StfServer.main rest
  | _ =>
    IO.eprintln "Usage: jar-stf --variant <variant> [--bless] <sub-transition> <input|dir>"
    IO.eprintln "Variants: gp072_tiny, gp072_full, jar1"
    return 1
