import Jar.Test.Properties
import Jar.Test.Arbitrary
import Jar.Variant

open Jar Jar.Test.Arb

def propertyMain : IO UInt32 := do
  letI := JamVariant.gp072_tiny.toJamConfig
  -- Provide variant-specific Arbitrary instances for EconType/TransferType.
  -- gp072_tiny uses BalanceEcon/BalanceTransfer.
  letI : Plausible.Arbitrary (JamConfig.EconType) := instArbitraryBalanceEcon
  letI : Plausible.Arbitrary (JamConfig.TransferType) := instArbitraryBalanceTransfer
  Jar.Test.Properties.runAll
